import { useState } from "react";
import { Button, Modal, Text } from "@mantine/core";
import { BiLogOut } from "react-icons/bi";
import useAuth from "@/shared/hooks/useAuth";

export default function Logout() {
  const auth = useAuth();
  const profilePictureShort = null;
  const [isLogoutConfirmOpen, setIsLogoutConfirmOpen] = useState(false);

  const handleConfirmLogout = async () => {
    await auth.signOut({ redirect: true });
    setIsLogoutConfirmOpen(false);
  };

  return (
    <>
      <div>
        <div className="flex items-center my-4 space-x-4 drop-shadow-md">
          {profilePictureShort ? (
            <Image
              src={profilePictureShort}
              alt="profile"
              width="50px"
              height="50px"
              className="h-12 w-12 object-cover rounded-full"
            />
          ) : (
            <div className="flex items-center justify-center h-12 w-12 rounded-full bg-blue-500 dark:bg-blue-700">
              <p className="text-2xl text-white">
                {(auth?.user?.name || " ").slice(0, 1)}
              </p>
            </div>
          )}
          <div>
            <p className="text-sm font-bold">{auth?.user?.name}</p>
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              {auth?.user?.username}
            </p>
          </div>
        </div>
        <div
          className="flex items-center space-x-4 bg-zinc-200 dark:bg-zinc-900 p-4 rounded-lg text-sm mt-2 justify-center cursor-pointer"
          onClick={() => setIsLogoutConfirmOpen(true)}
        >
          <BiLogOut size={20} />
          <p className="font-medium">Log out</p>
        </div>
      </div>

      <Modal
        opened={isLogoutConfirmOpen}
        onClose={() => setIsLogoutConfirmOpen(false)}
        title="Log out?"
        centered
      >
        <Text size="sm" c="dimmed">
          You will be signed out of your current session.
        </Text>
        <div className="mt-5 flex justify-end gap-3">
          <Button variant="default" onClick={() => setIsLogoutConfirmOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirmLogout}
            className="!bg-red-600 !text-red-50 hover:!bg-red-700"
          >
            Log out
          </Button>
        </div>
      </Modal>
    </>
  );
}
