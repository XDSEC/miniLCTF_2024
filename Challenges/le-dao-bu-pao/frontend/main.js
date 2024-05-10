"use strict";

// references: http://localhost:8080/docs
const API_BASE = location.origin;

document.addEventListener("alpine:init", () => {
  Alpine.data("songlist", () => ({
    songs: [
      {
        title: "春日影（Haruhikage）「BanG Dream! It's MyGO!!!!!」#7 插曲",
        url: "https://www.bilibili.com/video/BV1v14y1z7MV",
      },
      {
        title: "【Official Music Video】輪符雨（Refrain）/ MyGO!!!!!【原创歌曲】",
        url: "https://www.bilibili.com/video/BV1rC41157Ci",
      },
      {
        title: "【中日歌词MV/东映】「皆无其名」-トゲナシトゲアリ【动画GIRLS BAND CRY】",
        url: "https://www.bilibili.com/video/BV1924y1A731",
      },
      {
        title: "稲葉曇『私は雨』Vo. 歌愛ユキ / 稻叶昙 - 我是雨 (Vo. 歌爱雪)",
        url: "https://www.bilibili.com/video/BV1EE421M7zP",
      },
    ],
    song: {},

    randomSong() {
      this.song = this.songs[Math.floor(Math.random() * this.songs.length)];
    },

    init() {
      this.randomSong();
      setInterval(() => this.randomSong(), 180000);
    },
  }));

  Alpine.data("anticheat", () => ({
    accl: { x: 0, y: 0, z: 0 },
    rot: { alpha: 0, beta: 0, gamma: 0 },
    int: 0,

    // Do you really think that there is an anti-cheat system?
    _handler: (event) => {
      this.accl = event.acceleration;
      this.rot = event.rotationRate;
      this.int = event.interval;
    },

    init() {
      addEventListener("devicemotion", this._handler);
    },

    destroy() {
      removeEventListener("devicemotion", this._handler);
    },
  }));

  Alpine.store("status", {
    data: {
      status: "",
      distance: 0,
      flag: "",
    },
    ckpts: [],
    async update() {
      await fetch(API_BASE + "/status")
        .then((response) => response.json())
        .then((data) => {
          this.data = data;
        });
      await fetch(API_BASE + "/checkpoints")
        .then((response) => response.json())
        .then((data) => {
          this.ckpts = data.checkpoints;
        });
    },
  });

  Alpine.store("position", {
    coords: {
      latitude: 0,
      longitude: 0,
    },
    timestamp: 0,
  });

  Alpine.store("startTime", 0);
});

// ----------------------------

let updateTimer;
let geoWatcher;

async function reportPosition(position) {
  if (!position) return;
  await fetch(API_BASE + "/location", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      lat: position.coords.latitude,
      lon: position.coords.longitude,
    }),
  });
}

async function startRunning() {
  // Restart game
  await fetch(API_BASE + "/restart");
  await Alpine.store("status").update();

  // Stop the previous timer if it exists
  geoWatcher && navigator.geolocation.clearWatch(geoWatcher);
  updateTimer && clearInterval(updateTimer);

  console.log("start running");
  Alpine.store("startTime", new Date());

  geoWatcher = navigator.geolocation.watchPosition(
    (pos) => {
      console.debug("new position", pos);
      Alpine.store("position", pos);
    },
    console.error,
    {
      enableHighAccuracy: true,
      maximumAge: 1000,
    }
  );

  updateTimer = setInterval(async () => {
    await reportPosition(Alpine.store("position"));
    await Alpine.store("status").update();
    console.debug("reported at " + new Date());
  }, 5000);
}

// TODO: this should work, not tested. whatever, osu! qi dong!
// WARN: you shouldn't actually take your phone and run. who wants to do that?
