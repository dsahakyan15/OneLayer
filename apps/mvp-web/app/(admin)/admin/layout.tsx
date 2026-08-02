import type { ReactNode } from "react";
import { AdminShell } from "../../../components/admin-session";

export default function AdminLayout({ children }: { children: ReactNode }): ReactNode {
  return <AdminShell>{children}</AdminShell>;
}
