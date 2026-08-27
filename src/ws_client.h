#pragma once
#include <Arduino.h>

void        ws_client_init();
void        ws_client_tick();
bool        ws_client_connected();
void        ws_client_graceful_close();   // ramka WS close 1000 przed ESP.restart() (anty-ghost)
bool        ws_client_send_raw(const char* json_msg);
void        ws_client_send_push(const char* title, const char* body);

