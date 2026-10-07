"""Guided live workflow; every result comes from the local service, never fixtures."""
import json
import threading
import uuid

from live_demo_session import LiveDemoError, ProtocolError, configured_identities


class WorkflowScenario:
    def __init__(self, api):
        self.api = api
        self.session = None
        self.draft = None
        self.review = None
        self.publication = None
        self.certificate = None
        self.package = None
        self.qr = None
        self.verification = None
        self.tampered = None
        self.history = []

    def login(self, username):
        self.review = None  # a new identity must review afresh before signing
        self.api.sign_out()
        self.session = None
        identity = self.api.verify_served_identity()
        if not identity['matches']:
            raise ProtocolError('error', 'PROFILE_IDENTITY_MISMATCH')
        self.session = self.api.sign_in(username).as_dict()
        return self.session

    def create(self, record_id, payload):
        base = 0
        if self.draft and self.draft['state'] == 'COMMITTED' and self.draft.get('recordId') == record_id:
            base = self.draft['committed']['version']
        draft = self.api.create_workflow_draft(record_id=record_id, base_version=base,
            operation='upsert', payload=payload, idempotency_key=str(uuid.uuid4()))
        draft['recordId'] = record_id
        self.draft = draft
        self.review = self.publication = self.certificate = self.package = self.qr = None
        self.verification = self.tampered = None
        return draft

    def draft_action(self, action, payload=None):
        if not self.draft:
            raise ProtocolError('error', 'DRAFT_REQUIRED')
        d = self.draft
        args = dict(expected_revision=d['revision'], idempotency_key=str(uuid.uuid4()))
        if action == 'edit':
            result = self.api.edit_workflow_draft(d['draftId'], operation='upsert', payload=payload, **args)
        else:
            args.update(payload_hash=d['payloadHash'], base_version=d['baseVersion'])
            result = getattr(self.api, action + '_workflow_draft')(d['draftId'], **args)
        result['recordId'] = d['recordId']
        self.draft = result
        self.review = None
        return result

    def inspect(self):
        identity = self.api.verify_served_identity()
        if not identity['matches']:
            raise ProtocolError('error', 'PROFILE_IDENTITY_MISMATCH')
        review = self.api.review_publication()
        r = review.as_dict()
        if (r.get('cluster') != self.api.profile.expected_cluster
                or r.get('programId') != identity['served']['programId']
                or r.get('configPda') != identity['served']['configPda']):
            raise ProtocolError('error', 'PUBLICATION_IDENTITY_MISMATCH')
        if not self.draft or not any(m['recordId'] == self.draft['recordId']
                and m['version'] == self.draft['committed']['version'] for m in r['members']):
            raise ProtocolError('error', 'RECORD_NOT_IN_PUBLICATION')
        self.review = r
        return r

    def publish(self, approved_review):
        # The UI passes the exact displayed plan. Never approve a refreshed plan silently.
        if self.review != approved_review or not approved_review.get('attemptPlanHash'):
            raise ProtocolError('error', 'REVIEW_REQUIRED')
        r = dict(approved_review)
        self.review = None
        # A lost response may hide a successful send. Keep the operation resumable,
        # and reconcile without approving or signing another attempt.
        self.publication = {'status': 'UNKNOWN', 'operationId': r['operationId']}
        result = self.api.run_publication(operation_id=r['operationId'],
            approved_attempt_plan_hash=r['attemptPlanHash'], approved_intent_hash=r['intentHash'])
        self.publication = result
        return result

    def reconcile(self):
        if not self.publication or not self.publication.get('operationId'):
            raise ProtocolError('error', 'PUBLICATION_REQUIRED')
        op = self.publication['operationId']
        result = self.api.run_publication(operation_id=op, approved_attempt_plan_hash=None)
        if result['status'] == 'IDLE':
            state = self.api.durable_publications()
            row = next((x for x in state['operations'] if x['operationId'] == op), None)
            anchor = next((x for x in state['anchors'] if x['operationId'] == op), None)
            if row and row['state'] == 'FINALIZED' and anchor:
                result = dict(anchor, status='FINALIZED')
            else:
                raise ProtocolError('error', 'PUBLICATION_NOT_LEASED')
        self.publication = result
        return result

    def issue(self):
        if not self.publication or self.publication['status'] != 'FINALIZED':
            raise ProtocolError('error', 'FINALIZED_REQUIRED')
        if self.publication.get('slot') is None:
            raise ProtocolError('error', 'ANCHOR_SLOT_UNAVAILABLE')
        d = self.draft
        cert = self.api.issue_workflow_certificate(self.publication['operationId'],
            d['recordId'], d['committed']['version'],
            disclosed_paths=['payload.status', 'payload.areaSquareMeters'])
        package = self.api.get_certificate_package(cert['certificateId'])
        qr = self.api.get_qr_image(cert['certificateId'])
        self.certificate, self.package, self.qr = cert, package, qr
        return cert

    def load_certificate(self, certificate_id):
        package = self.api.get_certificate_package(certificate_id)
        qr = self.api.get_qr_image(certificate_id)
        self.certificate = {'certificateId': certificate_id, 'certificateHash': package.certificate_hash_hex}
        self.package, self.qr = package, qr
        self.verification = self.tampered = None
        return self.certificate

    def verify(self, tamper=False):
        if self.package is None:
            raise ProtocolError('error', 'CERTIFICATE_REQUIRED')
        data = self.package.package_bytes
        if tamper:
            data = data[:-1] + bytes([data[-1] ^ 1])
        report = self.api.verify_package(data, expected_hash_hex=self.certificate['certificateHash']).as_dict()
        if tamper:
            self.tampered = report
        else:
            self.verification = report
        return report

    def export(self, path):
        if self.package is None:
            raise ProtocolError('error', 'CERTIFICATE_REQUIRED')
        # Exclusive creation: never overwrite an existing document or follow a symlink.
        with open(path, 'x', encoding='utf8') as f:
            json.dump({'package_base64url': self.package.package_base64url,
                       'certificateHash': self.certificate['certificateHash'],
                       'qrUrl': self.package.qr_url}, f, ensure_ascii=False)
        return {'saved': str(path)}


def build_page(api, window):
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, GdkPixbuf
    from launcher_view import _label, _add_classes, _scrolled

    class WorkflowPage:
        def __init__(self):
            self.scenario = WorkflowScenario(api)
            self.busy = False
            self.closed = False
            self.last_error = None
            self.buttons = {}
            self.poll_id = None
            self.reconcile_failures = 0
            self.title = _label('Запись → согласование → блокчейн → сертификат', 'card-title', wrap=True)
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            page.set_border_width(20)
            page.pack_start(self.title, False, False, 0)
            page.pack_start(_label('Локальная синтетическая сеть • реальные запросы и транзакции', 'subtle'), False, False, 0)
            self.state = _label('Начните со входа registry_worker-1.', 'chip', 'chip-idle', wrap=True)
            page.pack_start(self.state, False, False, 0)
            self.status = _label('', 'subtle', wrap=True)
            page.pack_start(self.status, False, False, 0)
            session = Gtk.Box(spacing=8)
            self.identity = Gtk.ComboBoxText()
            usernames = configured_identities()
            for name in usernames:
                self.identity.append_text(name)
            self.identity.set_active(usernames.index('registry_worker-1') if 'registry_worker-1' in usernames else 0)
            session.pack_start(self.identity, True, True, 0)
            self.button(session, 'login', 'Войти / сменить пользователя', self.login)
            self.user = _label('Вход не выполнен', 'value')
            session.pack_start(self.user, False, False, 0)
            page.pack_start(session, False, False, 0)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            _add_classes(card, 'card')
            grid = Gtk.Grid(column_spacing=12, row_spacing=8)
            self.entries = {}
            for row, (key, label, default) in enumerate([
                    ('recordId', 'Номер записи', 'DEMO-' + uuid.uuid4().hex[:12]),
                    ('owner', 'Владелец', 'Demo owner'),
                    ('cadastralNumber', 'Кадастровый номер', '01-004-0123-045'),
                    ('areaSquareMeters', 'Площадь, м²', '1250'),
                    ('status', 'Статус', 'ACTIVE')]):
                entry = Gtk.Entry(); entry.set_text(default); entry.set_hexpand(True)
                grid.attach(_label(label, 'subtle'), 0, row, 1, 1); grid.attach(entry, 1, row, 1, 1)
                self.entries[key] = entry
            card.pack_start(grid, False, False, 0)
            row = Gtk.Box(spacing=6)
            self.button(row, 'new', 'Новая запись', self.new)
            self.button(row, 'create', '1. Создать черновик', self.create)
            self.button(row, 'edit', 'Изменить', lambda: self.action('edit'))
            self.button(row, 'submit', '2. На согласование', lambda: self.action('submit'))
            card.pack_start(row, False, False, 0)
            row = Gtk.Box(spacing=6)
            self.button(row, 'approve', '3. Согласовать', lambda: self.action('approve'))
            self.button(row, 'reject', 'Отклонить', lambda: self.action('reject'))
            self.button(row, 'commit', '4. Зафиксировать', lambda: self.action('commit'))
            card.pack_start(row, False, False, 0)
            self.draft_detail = _label('Согласовать должен другой пользователь с ролью registry_approver.', 'subtle', wrap=True)
            card.pack_start(self.draft_detail, False, False, 0)
            page.pack_start(card, False, False, 0)
            row = Gtk.Box(spacing=6)
            self.button(row, 'review', '5. Проверить план', self.inspect)
            self.button(row, 'publish', '6. Подтвердить публикацию…', self.confirm)
            self.button(row, 'reconcile', 'Обновить подтверждение', lambda: self.run('reconcile', self.scenario.reconcile))
            page.pack_start(row, False, False, 0)
            self.review_text = _label('Для публикации войдите как operator.', 'subtle', wrap=True, max_chars=76)
            self.review_text.set_selectable(True)
            page.pack_start(self.review_text, False, False, 0)
            row = Gtk.Box(spacing=6)
            self.button(row, 'issue', '7. Получить сертификат / QR', lambda: self.run('issue', self.scenario.issue))
            self.button(row, 'verify', '8. Проверить сертификат', lambda: self.run('verify', self.scenario.verify))
            self.button(row, 'tamper', 'Проверить изменённую копию', lambda: self.run('tamper', lambda: self.scenario.verify(True)))
            page.pack_start(row, False, False, 0)
            row = Gtk.Box(spacing=8)
            self.certificate_id = Gtk.Entry(); self.certificate_id.set_placeholder_text('ID готового сертификата')
            self.certificate_id.set_hexpand(True); row.pack_start(self.certificate_id, True, True, 0)
            self.button(row, 'load', 'Открыть сертификат', self.load_certificate)
            page.pack_start(row, False, False, 0)
            row = Gtk.Box(spacing=8)
            self.qr_image = Gtk.Image(); row.pack_start(self.qr_image, False, False, 0)
            self.result = _label('Сертификат ещё не выпущен.', 'value', wrap=True, max_chars=65)
            self.result.set_selectable(True); row.pack_start(self.result, True, True, 0)
            self.button(row, 'export', 'Сохранить JSON…', self.export)
            page.pack_start(row, False, False, 0)
            self.widget = _scrolled(page)
            window.connect('destroy', self.close)
            self.render()

        def button(self, row, key, text, fn):
            button = Gtk.Button(label=text)
            _add_classes(button, 'accent' if key in ('publish', 'verify') else 'ghost')
            button.connect('clicked', lambda _: fn())
            row.pack_start(button, False, False, 0); self.buttons[key] = button

        def payload(self):
            area = int(self.entries['areaSquareMeters'].get_text())
            if area < 1 or area > 2147483647:
                raise ValueError('area')
            return dict(owner=self.entries['owner'].get_text(), cadastralNumber=self.entries['cadastralNumber'].get_text(),
                        areaSquareMeters=area, status=self.entries['status'].get_text())

        def login(self):
            if self.poll_id:
                GLib.source_remove(self.poll_id)
                self.poll_id = None
            username = self.identity.get_active_text()
            self.run('login', lambda: self.scenario.login(username))

        def new(self):
            self.scenario.draft = None
            self.scenario.review = self.scenario.publication = None
            self.scenario.certificate = self.scenario.package = self.scenario.qr = None
            self.scenario.verification = self.scenario.tampered = None
            self.entries['recordId'].set_text('DEMO-' + uuid.uuid4().hex[:12]); self.render()

        def create(self):
            try:
                payload = self.payload(); rid = self.entries['recordId'].get_text()
            except ValueError:
                self.status.set_text('Введите целую положительную площадь.'); return
            self.run('create', lambda: self.scenario.create(rid, payload))

        def action(self, action):
            try:
                payload = self.payload() if action == 'edit' else None
            except ValueError:
                self.status.set_text('Введите целую положительную площадь.'); return
            self.run(action, lambda: self.scenario.draft_action(action, payload))

        def inspect(self):
            self.run('review', self.scenario.inspect)

        def confirm(self):
            r = self.scenario.review
            if not r:
                return
            dialog = Gtk.MessageDialog(transient_for=window, modal=True, message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.OK_CANCEL, text='Опубликовать проверенный пакет?')
            dialog.format_secondary_text(f"Сеть: {r['cluster']}\nЗаписей: {r['leafCount']}\nКомиссия: {r['feeLamports']} lamports\nПлан: {r['attemptPlanHash']}\nБудет подписана именно эта транзакция.")
            response = dialog.run(); dialog.destroy()
            if response == Gtk.ResponseType.OK:
                approved = dict(r)
                self.run('publish', lambda: self.scenario.publish(approved))

        def load_certificate(self):
            certificate_id = self.certificate_id.get_text().strip()
            self.run('load', lambda: self.scenario.load_certificate(certificate_id))

        def export(self):
            dialog = Gtk.FileChooserDialog(title='Сохранить сертификат', transient_for=window,
                action=Gtk.FileChooserAction.SAVE)
            dialog.add_buttons('Отмена', Gtk.ResponseType.CANCEL, 'Сохранить', Gtk.ResponseType.OK)
            dialog.set_current_name('onelayer-certificate.json')
            response = dialog.run(); path = dialog.get_filename(); dialog.destroy()
            if response == Gtk.ResponseType.OK:
                self.run('export', lambda: self.scenario.export(path))

        def run(self, action, fn):
            if self.busy or self.closed:
                return
            self.busy = True; self.last_error = None
            self.status.set_text('Выполняется: ' + action + '…'); self.render()
            def work():
                try:
                    result = fn(); error = None
                except LiveDemoError as e:
                    result = None; error = getattr(e, 'code', None) or ('HTTP_' + str(e.status) if hasattr(e, 'status') else e.detail or e.state)
                except Exception:
                    result = None; error = 'REQUEST_FAILED'
                GLib.idle_add(self.complete, action, result, error)
            threading.Thread(target=work, daemon=True).start()

        def complete(self, action, result, error):
            if self.closed:
                return False
            self.busy = False; self.last_error = error
            self.scenario.history.append({'action': action, 'result': result, 'error': error})
            rejected_copy = action == 'tamper' and result and result.get('status') == 'INVALID'
            self.status.set_text('Отказ: ' + error if error else
                'Изменённая копия отклонена: ' + str(result.get('code')) if rejected_copy else 'Готово: ' + action)
            context = self.status.get_style_context()
            context.remove_class('chip-bad')
            if error or rejected_copy:
                context.add_class('chip-bad')
            self.render()
            if action in ('issue', 'verify', 'tamper', 'load') and not error:
                GLib.timeout_add(100, self.scroll_result)
            p = self.scenario.publication
            if action == 'reconcile':
                self.reconcile_failures = self.reconcile_failures + 1 if error else 0
            transient = error in ('HTTP_503', 'offline') and self.reconcile_failures <= 5
            if action in ('publish', 'reconcile') and (not error or transient) and p and p['status'] in ('SUBMITTED', 'PENDING', 'UNKNOWN'):
                self.poll_id = GLib.timeout_add(1500, self.poll)
            return False

        def scroll_result(self):
            if not self.closed:
                adjustment = self.widget.get_vadjustment()
                adjustment.set_value(max(0, adjustment.get_upper() - adjustment.get_page_size()))
            return False

        def poll(self):
            self.poll_id = None
            if not self.closed and not self.busy:
                self.run('reconcile', self.scenario.reconcile)
            return False

        def render(self):
            s = self.scenario; d = s.draft; role = (s.session or {}).get('role')
            if s.certificate:
                self.certificate_id.set_text(s.certificate['certificateId'])
            self.user.set_text((s.session or {}).get('username', '') + (' • ' + role if role else 'Вход не выполнен'))
            state = d['state'] if d else 'Нет черновика'
            p = s.publication
            next_step = {'DRAFT': 'Отправьте на согласование.', 'SUBMITTED': 'Войдите registry_approver-1 и согласуйте.',
                         'APPROVED': 'Войдите registry_worker-1 и зафиксируйте.', 'COMMITTED': 'Войдите operator и проверьте план.',
                         'REJECTED': 'Исправьте черновик и отправьте повторно.'}.get(state, 'Войдите registry_worker-1 и создайте черновик.')
            if p:
                next_step = 'Выпустите сертификат.' if p['status'] == 'FINALIZED' else 'Ожидается подтверждение: ' + p['status']
            if s.certificate:
                next_step = 'Проверьте сертификат или сохраните файл.'
            if s.verification and s.verification.get('proofsStatus') == 'VERIFIED':
                next_step = 'Доказательства проверены. Можно начать новую запись.'
            self.state.set_text(state + ' • ' + next_step)
            if d:
                self.draft_detail.set_text(f"{d['recordId']} • ревизия {d['revision']} • версия базы {d['baseVersion']}\nХеш данных: {d['payloadHash']}")
            r = s.review
            if r:
                self.review_text.set_text(f"{r['cluster']} • пакет {r['batchSequence']} • записей {r['leafCount']} • комиссия {r.get('feeLamports')} lamports\nПрограмма: {r['programId']}\nПлан: {r.get('attemptPlanHash')}\nСимуляция: {r.get('simulation')}\nЗаписи: " + ', '.join(m['recordId'] for m in r['members']))
            elif p:
                self.review_text.set_text(f"Публикация: {p['status']}\nПодпись: {p.get('signature', '—')}\nСлот: {p.get('slot', '—')}")
            else:
                self.review_text.set_text('Для публикации войдите как operator и проверьте план.')
            if s.qr:
                loader = GdkPixbuf.PixbufLoader.new_with_type('png'); loader.write(s.qr); loader.close()
                self.qr_image.set_from_pixbuf(loader.get_pixbuf().scale_simple(136, 136, GdkPixbuf.InterpType.NEAREST))
            else:
                self.qr_image.clear()
            if s.verification:
                v = s.verification
                text = f"Сертификат: {v['certificateId']}\nДоказательства: {v.get('proofsStatus')} • реестр: {v.get('registryStatus')}\nАктуальность: {v['status']} • {v.get('lifecycleStatus')}\nИндекс инцидентов: {v.get('incidentIndexStatus')}\nРаскрытые поля: {json.dumps(v.get('disclosedFields'), ensure_ascii=False)}"
                if s.tampered:
                    text += f"\nИзменённая копия: {s.tampered['status']} • {s.tampered.get('code')}"
                self.result.set_text(text)
            elif s.certificate:
                self.result.set_text('Сертификат выпущен: ' + s.certificate['certificateId'] + '\nРаскрыты только статус и площадь. Нажмите «Проверить сертификат».')
            else:
                self.result.set_text('Сертификат ещё не выпущен.')
            allowed = {
                'login': True, 'new': not p or p['status'] in ('FINALIZED', 'FAILED', 'ERROR'), 'load': True,
                'create': role == 'registry_worker' and (not d or state == 'COMMITTED'),
                'edit': role == 'registry_worker' and d and state != 'COMMITTED',
                'submit': role == 'registry_worker' and state == 'DRAFT',
                'approve': role == 'registry_approver' and state == 'SUBMITTED',
                'reject': role == 'registry_approver' and state == 'SUBMITTED',
                'commit': role == 'registry_worker' and state == 'APPROVED',
                'review': role == 'operator' and state == 'COMMITTED' and not (p and p['status'] == 'FINALIZED'),
                'publish': role == 'operator' and r and not r.get('blockedReason') and r.get('attemptPlanHash') and r.get('simulation', {}).get('ok'),
                'reconcile': role == 'operator' and p and p['status'] != 'FINALIZED',
                'issue': role == 'operator' and p and p['status'] == 'FINALIZED' and p.get('slot') is not None,
                'verify': bool(s.package), 'tamper': bool(s.package and s.verification), 'export': bool(s.package),
            }
            for key, button in self.buttons.items():
                button.set_sensitive(bool(allowed[key]) and not self.busy)
            self.identity.set_sensitive(not self.busy)
            for entry in self.entries.values():
                entry.set_sensitive(not self.busy)

        def close(self, *_):
            self.closed = True
            if self.poll_id:
                GLib.source_remove(self.poll_id)
                self.poll_id = None
    return WorkflowPage()
