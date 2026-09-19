import { redirect } from "next/navigation";

export default function ChangesRedirectPage() {
  redirect("/projects/default/changes");
}
