# Voice Keyboard firmware for ESP32 and ESP32-C3: types dictation as a
# Bluetooth LE keyboard. Built in Docker by build.sh; no local toolchain.
cmake_minimum_required(VERSION 3.16)
if(DEFINED ENV{VK_VERSION})
  set(PROJECT_VER "$ENV{VK_VERSION}")
else()
  set(PROJECT_VER "dev")
endif()
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(porthub_keyboard)
