/* DEEP SAT EXPLOIT — 3D mission situational-awareness globe.
 * Ground stations are clickable (challenge connection info); satellites orbit,
 * and a compromised OBC makes its satellite spiral in and burn up on reentry. */

(function () {
  "use strict";

  function loadThree(cb) {
    if (window.THREE) return cb();
    var s = document.createElement("script");
    s.src = "https://unpkg.com/three@0.149.0/build/three.min.js";
    s.onload = function () { cb(); };
    s.onerror = function () { document.getElementById("err").style.display = "flex"; };
    document.head.appendChild(s);
  }

  loadThree(init);

  // ---- tunables ----
  var R = 100;                     // earth radius (scene units)
  var DEORBIT_DUR = 7.0;           // seconds from compromise to burn-up
  var DEG = Math.PI / 180;
  var RENDER_SCALE = 0.7;          // render below CSS size, upscale -- big fragment-shading saving

  var scene, camera, renderer, world, raycaster, mouse;
  var stationMeshes = [], sats = {}, stations = {};
  var explosions = [];
  var t0 = performance.now() / 1000;
  var lastState = null;
  var RED = null;                  // reentry heat color (set once THREE is loaded)
  var FPS = 20, FRAME = 1 / FPS, frameAcc = 0, prevFrameT = performance.now() / 1000;  // cap render rate

  function orbitRadius(o) { return R + 20 + (o.altitude_km || 500) * 0.03; }

  function llToVec(lat, lon, r) {
    var phi = (90 - lat) * DEG, theta = (lon + 180) * DEG;
    return new THREE.Vector3(
      -r * Math.sin(phi) * Math.cos(theta),
       r * Math.cos(phi),
       r * Math.sin(phi) * Math.sin(theta));
  }

  function orbitPos(o, a) {
    var r = orbitRadius(o);
    var v = new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r);
    v.applyAxisAngle(new THREE.Vector3(1, 0, 0), (o.inclination_deg || 0) * DEG);
    v.applyAxisAngle(new THREE.Vector3(0, 1, 0), (o.raan_deg || 0) * DEG);
    return v;
  }

  function init() {
    var canvas = document.getElementById("globe");
    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: false, powerPreference: "low-power" });
    renderer.setPixelRatio(1);   // render at 1x device pixels -- light on the GPU
    renderer.setSize(Math.floor(window.innerWidth * RENDER_SCALE), Math.floor(window.innerHeight * RENDER_SCALE), false);

    scene = new THREE.Scene();
    RED = new THREE.Color(0xff5533);
    camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 1, 4000);
    camera.position.set(0, 60, 330);

    world = new THREE.Group();
    scene.add(world);

    scene.add(new THREE.AmbientLight(0x2a3550, 1.0));
    var sun = new THREE.DirectionalLight(0xbfd4ff, 1.4);
    sun.position.set(-300, 120, 220);
    scene.add(sun);

    buildStars();
    buildEarth();

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    window.addEventListener("resize", onResize);
    setupControls(canvas);

    poll();
    setInterval(poll, 1000);
    animate();
  }

  function buildStars() {
    var g = new THREE.BufferGeometry(), n = 350, pos = new Float32Array(n * 3);
    for (var i = 0; i < n; i++) {
      var v = new THREE.Vector3().randomDirection().multiplyScalar(1500 + Math.random() * 900);
      pos[i * 3] = v.x; pos[i * 3 + 1] = v.y; pos[i * 3 + 2] = v.z;
    }
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    scene.add(new THREE.Points(g, new THREE.PointsMaterial({ color: 0x8899bb, size: 2, sizeAttenuation: false })));
  }

  function buildEarth() {
    // ocean sphere
    var earth = new THREE.Mesh(
      new THREE.SphereGeometry(R, 24, 18),
      new THREE.MeshPhongMaterial({ color: 0x0b2545, emissive: 0x04101f, shininess: 8, specular: 0x224466 }));
    world.add(earth);

    // graticule
    var grat = new THREE.Mesh(
      new THREE.SphereGeometry(R * 1.002, 16, 12),
      new THREE.MeshBasicMaterial({ color: 0x2b6ea6, wireframe: true, transparent: true, opacity: 0.18 }));
    world.add(grat);

    // stylized landmass speckle so it reads as a planet, not a ball
    var lg = new THREE.BufferGeometry(), n = 500, pos = new Float32Array(n * 3);
    for (var i = 0; i < n; i++) {
      var v = new THREE.Vector3().randomDirection();
      // clump into a few "continents" using a cheap noise-ish threshold
      var f = Math.sin(v.x * 3.1) * Math.cos(v.y * 2.3) + Math.sin(v.z * 2.7 + v.x);
      if (f < 0.25) { i--; continue; }
      v.multiplyScalar(R * 1.004);
      pos[i * 3] = v.x; pos[i * 3 + 1] = v.y; pos[i * 3 + 2] = v.z;
    }
    lg.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    world.add(new THREE.Points(lg, new THREE.PointsMaterial({ color: 0x2f9e6f, size: 1.6, sizeAttenuation: false })));
  }

  // ---- ground stations ----
  function addStation(gs) {
    var v = llToVec(gs.lat, gs.lon, R * 1.01);
    var color = gs.playable ? 0x7dd3fc : 0x9fb2c8;
    var pin = new THREE.Mesh(
      new THREE.SphereGeometry(gs.playable ? 2.2 : 1.6, 16, 12),
      new THREE.MeshBasicMaterial({ color: color }));
    pin.position.copy(v);
    pin.userData = gs;
    world.add(pin);
    stationMeshes.push(pin);

    // vertical beacon + ground ring for playable stations
    var halo = new THREE.Mesh(
      new THREE.RingGeometry(2.6, 4.2, 24),
      new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.5, side: THREE.DoubleSide }));
    halo.position.copy(v);
    halo.lookAt(0, 0, 0);
    world.add(halo);
    stations[gs.id] = { pin: pin, halo: halo, gs: gs };
  }

  // ---- satellites ----
  // a little cartoon spacecraft: gold body + two solar wings + a whip antenna.
  // returns { group, hot: [materials that glow red on reentry] }
  function makeSatModel(accent) {
    var g = new THREE.Group(), hot = [];
    var armMat = new THREE.MeshBasicMaterial({ color: 0x9aa4b0 });

    var bodyMat = new THREE.MeshLambertMaterial({ color: 0xcaa64a, emissive: 0x2a2410 });
    g.add(new THREE.Mesh(new THREE.BoxGeometry(3.0, 3.0, 4.0), bodyMat));
    hot.push(bodyMat);

    var panelMat = new THREE.MeshLambertMaterial({ color: 0x1c3f7a, emissive: 0x0a1a33 });
    for (var sgn = -1; sgn <= 1; sgn += 2) {
      var arm = new THREE.Mesh(new THREE.BoxGeometry(2.2, 0.22, 0.22), armMat);
      arm.position.x = sgn * 2.6; g.add(arm);
      var panel = new THREE.Mesh(new THREE.BoxGeometry(4.4, 0.16, 3.0), panelMat);
      panel.position.x = sgn * 5.9; g.add(panel);
    }
    hot.push(panelMat);

    var rod = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 2.6, 6), armMat);
    rod.position.y = 2.4; g.add(rod);
    var tipMat = new THREE.MeshBasicMaterial({ color: accent });
    var tip = new THREE.Mesh(new THREE.SphereGeometry(0.65, 10, 8), tipMat);
    tip.position.y = 3.9; g.add(tip); hot.push(tipMat);

    g.rotation.x = 0.4;   // jaunty tilt
    return { group: g, hot: hot };
  }

  function addSat(s) {
    var color = new THREE.Color(s.color || "#a7f3d0");
    var model = makeSatModel(color);
    var ring = orbitRing(s.orbit, color);
    world.add(model.group); world.add(ring);

    // reentry trail
    var trailGeo = new THREE.BufferGeometry();
    trailGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(60 * 3), 3));
    var trail = new THREE.Line(trailGeo, new THREE.LineBasicMaterial({ color: 0xff7a3c, transparent: true, opacity: 0.9 }));
    trail.visible = false; world.add(trail);

    sats[s.id] = {
      cfg: s, body: model.group,
      hot: model.hot.map(function (m) { return { mat: m, base: m.color.clone() }; }),
      ring: ring, color: color, trail: trail,
      onset: null, burned: false, angle: (s.orbit.phase_deg || 0) * DEG, trailPts: []
    };
  }

  function orbitRing(o, color) {
    var pts = [], N = 64;
    for (var i = 0; i <= N; i++) pts.push(orbitPos(o, (i / N) * Math.PI * 2));
    var g = new THREE.BufferGeometry().setFromPoints(pts);
    return new THREE.LineLoop(g, new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.28 }));
  }

  function spawnExplosion(pos) {
    var m = new THREE.Mesh(
      new THREE.SphereGeometry(2, 16, 12),
      new THREE.MeshBasicMaterial({ color: 0xffb347, transparent: true, opacity: 0.9 }));
    m.position.copy(pos); world.add(m);
    explosions.push({ mesh: m, age: 0 });
  }

  // ---- animation ----
  function animate() {
    requestAnimationFrame(animate);
    var now = performance.now() / 1000;
    frameAcc += now - prevFrameT;
    prevFrameT = now;
    if (frameAcc < FRAME) return;   // throttle to ~20fps to keep the GPU/CPU idle between frames
    frameAcc = 0;
    var t = now - t0;

    if (!isDragging) world.rotation.y += 0.0018;

    for (var id in sats) updateSat(sats[id], t, now);

    for (var i = explosions.length - 1; i >= 0; i--) {
      var e = explosions[i]; e.age += 0.016;
      e.mesh.scale.setScalar(1 + e.age * 22);
      e.mesh.material.opacity = Math.max(0, 0.9 - e.age * 1.3);
      if (e.age > 0.9) { world.remove(e.mesh); explosions.splice(i, 1); }
    }
    renderer.render(scene, camera);
  }

  function updateSat(sat, t, now) {
    var o = sat.cfg.orbit;
    var speed = (2 * Math.PI) / (o.period_s || 30);

    if (sat.onset === null) {
      // nominal orbit
      sat.angle = (o.phase_deg || 0) * DEG + t * speed;
      sat.body.position.copy(orbitPos(o, sat.angle));
      sat.body.rotation.y += 0.03;          // gentle tumble for character
      sat.body.visible = true;
      return;
    }

    if (sat.burned) { return; }

    var p = (now - sat.onset) / DEORBIT_DUR;     // 0..1 fall progress
    // spiral inward, accelerating
    sat.angle += speed * (1 + p * 6) * 0.016;
    var rNow = orbitRadius(o);
    var rFall = rNow + (R * 1.03 - rNow) * ease(p);
    var v = orbitPos(o, sat.angle).setLength(rFall);
    sat.body.position.copy(v);

    // heat the whole spacecraft red, tumble harder as it falls, fade the orbit
    var heat = Math.min(1, p * 1.4);
    for (var h = 0; h < sat.hot.length; h++) sat.hot[h].mat.color.lerpColors(sat.hot[h].base, RED, heat);
    sat.body.rotation.y += 0.06 + p * 0.22;
    sat.body.rotation.z += 0.04 + p * 0.16;
    sat.ring.material.opacity = 0.28 * (1 - p);

    // reentry trail
    sat.trailPts.push(v.clone());
    if (sat.trailPts.length > 60) sat.trailPts.shift();
    var arr = sat.trail.geometry.attributes.position.array;
    for (var i = 0; i < 60; i++) {
      var pt = sat.trailPts[i] || sat.trailPts[0] || v;
      arr[i * 3] = pt.x; arr[i * 3 + 1] = pt.y; arr[i * 3 + 2] = pt.z;
    }
    sat.trail.geometry.attributes.position.needsUpdate = true;
    sat.trail.visible = true;

    if (p >= 1) {
      spawnExplosion(v);
      sat.body.visible = false;
      sat.ring.visible = false;
      sat.trail.material.opacity = 0.0;
      sat.burned = true;
    }
  }

  function ease(x) { x = Math.max(0, Math.min(1, x)); return x * x * (3 - 2 * x); }

  // ---- polling / state ----
  function poll() {
    fetch("/api/state").then(function (r) { return r.json(); }).then(applyState).catch(function () {});
  }

  function applyState(st) {
    lastState = st;
    // build objects once
    if (stationMeshes.length === 0 && st.ground_stations) st.ground_stations.forEach(addStation);
    if (Object.keys(sats).length === 0 && st.satellites) st.satellites.forEach(addSat);

    // window badge
    var win = document.getElementById("win");
    win.textContent = st.window.state;
    win.className = st.window.state === "AOS" ? "" : "los";
    document.getElementById("wint").textContent = "T-" + st.window.remaining + "s";
    document.getElementById("solves").textContent = st.solve_count;

    // compromise transitions
    st.satellites.forEach(function (s) {
      var sat = sats[s.id];
      if (!sat) return;
      if (s.compromised && sat.onset === null) {
        // align local animation clock with server's elapsed time
        sat.onset = performance.now() / 1000 - (s.since || 0);
      }
      if (!s.compromised && sat.onset !== null) resetSat(sat);   // demo reset
    });

    // ticker
    var tick = document.getElementById("ticker");
    tick.innerHTML = "";
    (st.events || []).slice().reverse().forEach(function (e) {
      var d = document.createElement("div");
      d.textContent = e.msg;
      if (/compromis|orbit|escap/i.test(e.msg)) d.className = "hot";
      tick.appendChild(d);
    });

    // demo controls
    var demo = document.getElementById("demo");
    if (st.demo) { demo.style.display = "block"; if (!demo.dataset.built) buildDemo(demo); }

    if (panelStationId) renderPanel(stations[panelStationId].gs);   // live-refresh open panel
  }

  function resetSat(sat) {
    sat.onset = null; sat.burned = false;
    sat.body.visible = true; sat.ring.visible = true;
    sat.ring.material.opacity = 0.28;
    for (var h = 0; h < sat.hot.length; h++) sat.hot[h].mat.color.copy(sat.hot[h].base);
    sat.trail.visible = false; sat.trailPts = [];
  }

  function buildDemo(demo) {
    demo.dataset.built = "1";
    var b = document.createElement("button");
    b.textContent = "⚠ simulate SAT-1 hack";
    b.onclick = function () { post("/api/demo/compromise", { sat: "SAT-1" }); };
    var r = document.createElement("button");
    r.className = "reset"; r.textContent = "↺ reset orbit";
    r.onclick = function () { post("/api/demo/compromise", { sat: "SAT-1", reset: true }); };
    demo.appendChild(b); demo.appendChild(r);
  }

  function post(url, body) {
    fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(poll).catch(function () {});
  }

  // ---- ground station info panel ----
  var panelStationId = null;

  function satStatus(satId) {
    if (!lastState) return { cls: "op", label: "OPERATIONAL" };
    var s = (lastState.satellites || []).find(function (x) { return x.id === satId; });
    if (s && s.compromised) return { cls: "dn", label: "COMPROMISED · DE-ORBITING" };
    return { cls: "op", label: "OPERATIONAL" };
  }

  function renderPanel(gs) {
    panelStationId = gs.id;
    document.getElementById("p-name").textContent = gs.name;
    var ep = gs.endpoints || {};
    var stat = satStatus(gs.satellite);
    var html = "";
    html += '<div><span class="k">STATION</span> ' + gs.id + ' · ' + (gs.country || "") + '</div>';
    html += '<div><span class="k">TARGET SAT</span> <b>' + gs.satellite + '</b> ' +
            '<span class="status ' + stat.cls + '">' + stat.label + '</span></div>';
    if (gs.playable) {
      html += '<div style="margin-top:8px"><span class="status play">OPEN CHALLENGE</span></div>';
      if (ep.ground_station_web) html += '<div><span class="k">web mission control</span><br><code>' + ep.ground_station_web + '</code></div>';
      if (ep.uplink_relay_tcp) html += '<div><span class="k">uplink relay (tcp)</span><br><code>' + ep.uplink_relay_tcp + '</code></div>';
      html += '<div class="cta">' + (ep.note || "") + '</div>';
    } else {
      html += '<div class="cta" style="margin-top:10px">' + (ep.note || "No open challenge on this pass.") + '</div>';
    }
    document.getElementById("p-body").innerHTML = html;
    document.getElementById("panel").style.display = "block";
  }

  window.closePanel = function () {
    document.getElementById("panel").style.display = "none";
    panelStationId = null;
  };

  // ---- controls: drag to rotate, wheel to zoom, click to select ----
  var isDragging = false, downX = 0, downY = 0, lastX = 0, lastY = 0, moved = 0;

  function setupControls(canvas) {
    canvas.addEventListener("pointerdown", function (e) {
      isDragging = true; moved = 0;
      downX = lastX = e.clientX; downY = lastY = e.clientY;
    });
    window.addEventListener("pointermove", function (e) {
      if (!isDragging) return;
      var dx = e.clientX - lastX, dy = e.clientY - lastY;
      moved += Math.abs(dx) + Math.abs(dy);
      world.rotation.y += dx * 0.005;
      world.rotation.x = Math.max(-1.2, Math.min(1.2, world.rotation.x + dy * 0.005));
      lastX = e.clientX; lastY = e.clientY;
    });
    window.addEventListener("pointerup", function (e) {
      isDragging = false;
      if (moved < 6) tryPick(e);      // treat as a click
    });
    canvas.addEventListener("wheel", function (e) {
      e.preventDefault();
      camera.position.z = Math.max(150, Math.min(650, camera.position.z + e.deltaY * 0.25));
    }, { passive: false });
  }

  function tryPick(e) {
    mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
    raycaster.setFromCamera(mouse, camera);
    var hits = raycaster.intersectObjects(stationMeshes, false);
    if (hits.length) renderPanel(hits[0].object.userData);
    else window.closePanel();
  }

  function onResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(Math.floor(window.innerWidth * RENDER_SCALE), Math.floor(window.innerHeight * RENDER_SCALE), false);
  }
})();
