import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog as Modal } from "@/components/ui/dialog";
import { BiLogOut } from "react-icons/bi";
import useAuth from "@/shared/hooks/useAuth";
import DarkThemeToggle from "./DarkThemeToggle";

export default function Logout({ collapsed = false }) {
  const auth = useAuth();
  const profilePictureShort = auth?.user?.profile_picture?.data_url || null;
  const [isLogoutConfirmOpen, setIsLogoutConfirmOpen] = useState(false);

  const handleConfirmLogout = async () => {
    await auth.signOut({ redirect: true });
    setIsLogoutConfirmOpen(false);
  };

  return (
    <>
      <div className="flex min-w-0 items-center gap-1">
        <div className="flex min-w-0 flex-1 items-center gap-2" title={auth?.user?.username}>
          {profilePictureShort ? (
            <img
              src={profilePictureShort}
              alt="profile"
              className="h-7 w-7 shrink-0 object-cover rounded-full"
            />
          ) : (
            <div className="flex shrink-0 items-center justify-center h-7 w-7 rounded-full bg-primary">
              <p className="text-base text-white">
                {(auth?.user?.name || " ").slice(0, 1)}
              </p>
            </div>
          )}
          <div className={collapsed ? "hidden" : "min-w-0"}>
            <p className="truncate text-xs font-semibold" title={auth?.user?.name}>{auth?.user?.name}</p>
          </div>
        </div>
        <div className="flex shrink-0 items-center">
        <DarkThemeToggle compact />
        <button
          type="button"
          title="Log out"
          aria-label="Log out"
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => setIsLogoutConfirmOpen(true)}
        >
          <BiLogOut size={20} />
        </button>
        </div>
      </div>

      <Modal
        opened={isLogoutConfirmOpen}
        onClose={() => setIsLogoutConfirmOpen(false)}
        title="Log out?"
        centered
      >
        <p className="text-sm leading-6 text-muted-foreground">
          You will be signed out of your current session.
        </p>
        <div className="mt-5 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setIsLogoutConfirmOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirmLogout}
            variant="destructive"
          >
            Log out
          </Button>
        </div>
      </Modal>
    </>
  );
}
