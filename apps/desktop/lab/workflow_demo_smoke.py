"""Explicit synthetic-local GTK smoke. Creates/publishes a disposable demo record.

Run via ./deploy/devnet-demo/live-demo check-scenario with the local stack up.
No public-chain writes. Artifacts contain only synthetic records and public proof.
"""
import sys,time,json,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import gi
gi.require_version('Gtk','3.0');gi.require_version('Gdk','3.0')
from gi.repository import Gtk,GLib,Gdk
from launcher_view import LauncherView
assert Gtk.init_check()[0]
window=Gtk.Window();window.set_default_size(1120,880)
view=LauncherView(window);window.show_all();page=view._workflow
import tempfile
base=tempfile.mkdtemp(prefix='onelayer-scenario-proof-')+'/'
assert page.scenario.api.profile.is_local_cluster
assert page.scenario.api.profile.registry_id=='demo.synthetic.local'
assert page.scenario.api.verify_served_identity()['matches']
print('EVIDENCE',base,flush=True)
def wait(fn,seconds=20):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  while Gtk.events_pending():Gtk.main_iteration_do(False)
  if fn():return
  time.sleep(.01)
 raise AssertionError(('Timeout',page.status.get_text(),page.scenario.history[-3:]))
def click(name):
 assert page.buttons[name].get_sensitive(),('disabled',name,page.scenario.session,page.scenario.draft)
 page.buttons[name].clicked();wait(lambda:not page.busy)
 assert not page.last_error,(name,page.last_error)
 print('PASS',name,page.status.get_text(),flush=True)
def login(name):
 model=page.identity.get_model()
 for n,row in enumerate(model):
  if row[0]==name:page.identity.set_active(n);break
 else:raise AssertionError(name)
 click('login')
def capture(name):
 end=time.monotonic()+.2
 while time.monotonic()<end:
  while Gtk.events_pending():Gtk.main_iteration_do(False)
  time.sleep(.01)
 while Gtk.events_pending():Gtk.main_iteration_do(False)
 import cairo
 window.check_resize()
 surface=cairo.ImageSurface(cairo.FORMAT_ARGB32,window.get_allocated_width(),window.get_allocated_height())
 window.draw(cairo.Context(surface));surface.write_to_png(base+name+'.png')
login('registry_worker-1');click('create');click('submit')
# A worker cannot approve. Exercise the actual guarded button/API denial.
assert not page.buttons['approve'].get_sensitive()
page.run('forbidden-approval',lambda:page.scenario.draft_action('approve'))
wait(lambda:not page.busy);assert page.last_error in ('PERMISSION_DENIED','ADMIN_PERMISSION_DENIED','FORBIDDEN','HTTP_403'),page.last_error
print('PASS permission refusal',page.last_error,flush=True)
login('registry_approver-1');click('reject')
assert page.scenario.draft['state']=='REJECTED'
login('registry_worker-1');page.entries['areaSquareMeters'].set_text('1251');click('edit');click('submit')
assert page.scenario.draft['revision']==2
login('registry_approver-1');click('approve')
login('registry_worker-1');click('commit')
login('operator');click('review');capture('scenario-plan')
def approve_dialog():
 for w in Gtk.Window.list_toplevels():
  if isinstance(w,Gtk.MessageDialog):w.response(Gtk.ResponseType.OK);return False
 return True
GLib.timeout_add(50,approve_dialog);click('publish')
wait(lambda:page.scenario.publication and page.scenario.publication['status']=='FINALIZED' and not page.busy,100)
print('FINALIZED',page.scenario.publication,flush=True)
click('issue');click('verify');capture('scenario-verified')
assert page.scenario.verification['proofsStatus']=='VERIFIED',page.scenario.verification
click('tamper');assert page.scenario.tampered['status']=='INVALID';capture('scenario-tamper')
export_path=base+'certificate-'+page.scenario.certificate['certificateId']+'.json'
def export_dialog():
 for w in Gtk.Window.list_toplevels():
  if isinstance(w,Gtk.FileChooserDialog):
   w.set_current_folder(base);w.set_current_name(os.path.basename(export_path))
   GLib.timeout_add(800,lambda:(w.response(Gtk.ResponseType.OK),False)[1]);return False
 return True
GLib.timeout_add(100,export_dialog);click('export')
report=page.scenario.api.verify_package_file(export_path).as_dict();assert report['proofsStatus']=='VERIFIED'
print('PASS exported certificate verification',flush=True)
json.dump(dict(recordId=page.scenario.draft['recordId'],draft=page.scenario.draft,publication=page.scenario.publication,certificate=page.scenario.certificate,verification=page.scenario.verification,tampered=page.scenario.tampered,history=page.scenario.history),open(base+'scenario-gtk-result.json','w'),indent=2)
print('GUI COMPLETE',flush=True)
window.destroy()
