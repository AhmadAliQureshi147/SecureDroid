import React from "react";
import { WebView } from "react-native-webview";
import AsyncStorage from "@react-native-async-storage/async-storage";

export function SessionScreen() {
  async function persist(token: string) {
    await AsyncStorage.setItem("auth_token", token);
  }

  return <WebView source={{ uri: "https://example.com" }} originWhitelist={["*"]} />;
}
