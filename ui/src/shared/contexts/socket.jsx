import React from "react";
import io from "socket.io-client";

const socket = io({
  path: "/socket.io",
  transports: ["websocket"],
  autoConnect: false,
});
const SocketContext = React.createContext();

export { socket, SocketContext };
