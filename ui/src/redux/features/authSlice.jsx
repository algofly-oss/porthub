import { createSlice } from "@reduxjs/toolkit";

const initialUserState = {
  name: null,
  username: null,
  role: "unknown",
  activated: false,
};

export const authSlice = createSlice({
  name: "auth",
  initialState: {
    user: initialUserState,
    connectionError: null,
  },
  reducers: {
    setAccountInfo: (state, action) => {
      state.user = action.payload;
      state.connectionError = null;
    },
    updateAccountInfo: (state, action) => {
      state.user = Object.assign(state.user, action.payload);
    },
    resetAccountInfo: (state) => {
      state.user = initialUserState;
      state.connectionError = null;
    },
    accountUnavailable: (state) => {
      state.connectionError = "Could not reconnect to PortHub. Your saved session has not been cleared.";
    },
  },
});

export const authActions = authSlice.actions;
export const authSelector = (state) => state.auth.user;
export default authSlice.reducer;
