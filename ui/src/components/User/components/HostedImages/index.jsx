import { useState } from "react";
import { Button } from "@/components/ui/button";
import Gallery from "./Gallery";
import Rooms from "./Rooms";
export default function HostedImages({ active = true }) {
  const [tab, setTab] = useState("images");
  return <div className="flex h-full min-h-0 flex-col">
    <div className="mx-auto flex w-full max-w-[1600px] shrink-0 gap-2 px-3 pt-3 sm:px-5" aria-label="Image sections">
      <Button className="focus-visible:ring-primary focus-visible:ring-offset-0" aria-pressed={tab === "images"} variant={tab === "images" ? "secondary" : "ghost"} size="sm" onMouseDown={event => event.preventDefault()} onClick={() => setTab("images")}>My images</Button>
      <Button className="focus-visible:ring-primary focus-visible:ring-offset-0" aria-pressed={tab === "rooms"} variant={tab === "rooms" ? "secondary" : "ghost"} size="sm" onMouseDown={event => event.preventDefault()} onClick={() => setTab("rooms")}>Public rooms</Button>
    </div>
    <div className={tab === "images" ? "min-h-0 flex-1" : "hidden"}><Gallery active={active && tab === "images"} /></div>
    <div className={tab === "rooms" ? "min-h-0 flex-1" : "hidden"}><Rooms active={active && tab === "rooms"} /></div>
  </div>;
}
