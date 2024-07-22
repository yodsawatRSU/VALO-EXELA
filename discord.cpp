#include "Discord.hpp"
#include <chrono>

void Discord::Initialize() {
	DiscordEventHandlers handle;
	memset(&handle, 0, sizeof(handle));
	Discord_Initialize("1204801231105560636", &handle, 1, NULL);
}

static int64_t eptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

void Discord::Update() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.startTimestamp = eptime;
    discordPresence.largeImageKey = "exelawhite";
    discordPresence.largeImageText = "Playing Valorant using Exela External";
    discordPresence.state = "Exela External";
    discordPresence.details = "Valorant Cheat";
    Discord_UpdatePresence(&discordPresence);
}