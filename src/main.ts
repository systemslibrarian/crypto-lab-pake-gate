// Entry point. Mounts the four-tab PAKE surface at #app. Vanilla DOM, no framework.

import "./styles.css";
import { mountApp } from "./ui/tabs.ts";

const root = document.getElementById("app");
if (!root) {
  throw new Error("mount point #app not found");
}
mountApp(root);
