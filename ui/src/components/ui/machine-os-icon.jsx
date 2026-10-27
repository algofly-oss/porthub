import { IconBrandApple, IconBrandWindows } from "@tabler/icons-react";
import { SiLinux, SiUbuntu, SiDebian, SiRedhat, SiRaspberrypi, SiFedora, SiAlpinelinux, SiArchlinux, SiLinuxmint, SiOpensuse, SiCentos } from "react-icons/si";

const distributions = {
  ubuntu: SiUbuntu, debian: SiDebian, rhel: SiRedhat, raspbian: SiRaspberrypi,
  raspberrypi: SiRaspberrypi, fedora: SiFedora, alpine: SiAlpinelinux,
  arch: SiArchlinux, linuxmint: SiLinuxmint, opensuse: SiOpensuse,
  "opensuse-leap": SiOpensuse, "opensuse-tumbleweed": SiOpensuse, centos: SiCentos,
};
export default function MachineOsIcon({ os, distribution, ...props }) {
  const Icon = os === "windows" ? IconBrandWindows : os === "macos" ? IconBrandApple : distributions[distribution] || SiLinux;
  return <Icon {...props} aria-hidden="true" />;
}
