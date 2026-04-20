import { useState } from "react";
import UserNavBar from "./components/NavBar";
import { VscRemoteExplorer } from "react-icons/vsc";
import Home from "./components/Home";
import Proxy from "./components/Proxy";
import { useRouter } from "next/router";
import uiRoutes from "@/shared/routes/uiRoutes";

export default function UserHome() {
  const router = useRouter();
  const [tab, setTab] = useState("Home");
  const [machineStats, setMachineStats] = useState({
    registered: 0,
    online: 0,
    offline: 0,
  });

  return (
    <div className="flex">
      <aside
        className="bg-neutral-100 dark:bg-black flex items-center w-full md:flex-col md:items-stretch md:px-4 fixed inset-x-0 bottom-0 z-10 h-16 md:h-screen md:w-60 2xl:w-84 md:p-4 md:overflow-y-auto md:light-scrollbar dark:md:dark-scrollbar"
      >
        <div
          className="hidden md:flex flex-shrink-0 space-x-3 items-center mt-2 mb-6 dark:text-neutral-300 cursor-pointer"
          onClick={() => {
            // router.push(uiRoutes.root);
          }}
        >
          <VscRemoteExplorer size={30} />
          <p className="font-bold md:text-lg">PortHub</p>
        </div>
        <UserNavBar tab={tab} setTab={setTab} machineStats={machineStats} />
      </aside>
      <div className="w-full md:ml-60 2xl:ml-84 md:h-screen md:overflow-y-auto md:light-scrollbar dark:md:dark-scrollbar">
        {tab === "Home" && <Home onStatsChange={setMachineStats} />}
        {tab === "Proxy" && <Proxy />}
      </div>
      {/* <div className="hidden lg:block w-[26rem] 2xl:w-[25%]- 2xl:w-[30rem] h-screen bg-neutral-100 dark:bg-black overflow-y-hidden md:light-scrollbar dark:md:dark-scrollbar"></div> */}
    </div>
  );
}
