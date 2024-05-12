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

/**
 * @param {Array<{lat: number, lon: number}>} _ckpts
 */ 
function* positionGenerator(_ckpts) {
    /** @type {Array<{lat: number, lon: number}>} */
    let ckpts = JSON.parse(JSON.stringify(_ckpts));
    let crt = 0;
    let nxt = 1;

    function calculateDistance(lat1, lon1, lat2, lon2) {
        const R = 6371e3; // metres
        const phi1 = lat1 * Math.PI / 180; // φ, λ in radians
        const phi2 = lat2 * Math.PI / 180;
        const dphi = (lat2-lat1) * Math.PI / 180;
        const dlam = (lon2-lon1) * Math.PI / 180;

        const a = Math.sin(dphi/2) * Math.sin(dphi/2) +
                  Math.cos(phi1) * Math.cos(phi2) *
                  Math.sin(dlam/2) * Math.sin(dlam/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

        return R * c; // in metres
    }

    function* interpolate(lat1, lon1, lat2, lon2, distance) {
        const total = calculateDistance(lat1, lon1, lat2, lon2);
        const step = distance / total;
        let t = 0;
        while (t < 1) {
            yield {
                lat: lat1 + t * (lat2 - lat1),
                lon: lon1 + t * (lon2 - lon1),
            };
            t += step;
        }
    }
    
    while (true) {
        let ckpt1 = ckpts[crt];
        let ckpt2 = ckpts[nxt];
        const generator = interpolate(ckpt1.lat, ckpt1.lon, ckpt2.lat, ckpt2.lon, 99); // not 100, fuck ieee 754
        for (const pos of generator) {
            yield pos;
        }
        crt = (crt + 1) % ckpts.length;
        nxt = (nxt + 1) % ckpts.length;
    }
}

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
      lat: position.lat,
      lon: position.lon,
    }),
  });
}

async function startRunning() {
  // Restart game
  await fetch(API_BASE + "/restart");
  await Alpine.store("status").update();

  // Stop the previous timer if it exists
  updateTimer && clearInterval(updateTimer);

  console.log("start running");
  Alpine.store("startTime", new Date());

  await Alpine.store("status").update();
  let posgen = positionGenerator(Alpine.store("status").ckpts);
  
  updateTimer = setInterval(async () => {
    let pos = posgen.next().value;
    Alpine.store("position").coords.latitude = pos.lat;
    Alpine.store("position").coords.longitude = pos.lon;
    Alpine.store("position").timestamp = Date.now();
    await reportPosition(pos);
    await Alpine.store("status").update();
    console.debug("reported at " + new Date());
  },3000);
}
