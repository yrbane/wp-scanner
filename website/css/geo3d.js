/**
 * geo3d — Lightweight 3D wireframe geometry animation
 *
 * Nested polyhedra rendered with Canvas 2D + manual 3D projection.
 * Configurable via URL parameters. Supports random generation.
 *
 * Features:
 *   - Mouse/touch-driven rotation (smooth lerp)
 *   - Per-layer configurable speed, scale, color, opacity
 *   - Pre-rendered glow sprites (offscreen canvas — zero per-frame gradient alloc)
 *   - Typed arrays for geometry & projection (cache-friendly, zero GC)
 *   - Analytically composed rotation matrix (single trig pass)
 *   - IntersectionObserver pause when off-screen
 *   - Timestamp-based animation (frame-rate independent)
 *   - URL parameters for full customization
 *   - Random mode for generative art
 *
 * Zero dependencies.
 *
 * License: MIT — https://github.com/yrbane/geo3d
 */
(function(){
  var c = document.getElementById('geo');
  if (!c) return;
  var ctx = c.getContext('2d');
  if (!ctx) return;

  /* ═══════════════════════════════════════════════════════════════════════
     URL PARAMETER PARSING
     ═══════════════════════════════════════════════════════════════════════ */
  function parseParams() {
    var params = {};
    var search = window.location.search.substring(1);
    if (!search) return params;
    var parts = search.split('&');
    for (var i = 0; i < parts.length; i++) {
      var kv = parts[i].split('=');
      var key = decodeURIComponent(kv[0]);
      var val = kv.length > 1 ? decodeURIComponent(kv[1]) : '';
      params[key] = val;
    }
    return params;
  }

  var PARAMS = parseParams();
  var isRandom = window.GEO3D_FORCE_RANDOM || 'random' in PARAMS;

  /* ═══════════════════════════════════════════════════════════════════════
     COLOR PRESETS
     ═══════════════════════════════════════════════════════════════════════ */
  var PRESETS = {
    default: ['108,99,255', '0,212,170', '255,107,107'],
    neon:    ['255,20,147', '57,255,20', '0,120,255', '255,0,255'],
    fire:    ['255,220,50', '255,140,0', '255,50,20', '200,30,0'],
    ice:     ['140,200,255', '220,240,255', '0,220,220', '180,220,255'],
    pastel:  ['255,182,193', '200,180,255', '152,251,178', '255,218,185'],
    mono:    ['255,255,255', '200,200,200', '160,160,160', '120,120,120'],
    gold:    ['255,215,0', '255,180,40', '205,133,63', '180,120,40'],
    matrix:  ['0,255,65', '0,200,50', '0,150,40'],
  };

  /* ═══════════════════════════════════════════════════════════════════════
     GEOMETRY CATALOGUE
     ═══════════════════════════════════════════════════════════════════════ */
  var phi = (1 + Math.sqrt(5)) / 2;

  function normalize(v) {
    var l = Math.sqrt(v[0]*v[0] + v[1]*v[1] + v[2]*v[2]);
    return [v[0]/l, v[1]/l, v[2]/l];
  }

  function normalizeAll(verts) {
    return verts.map(function(v) { return normalize(v); });
  }

  // Extract unique edges from face list
  function extractEdges(F) {
    var seen = {}, edges = [];
    F.forEach(function(f) {
      for (var i = 0; i < f.length; i++) {
        var a = f[i], b = f[(i+1) % f.length];
        var key = Math.min(a,b) + '_' + Math.max(a,b);
        if (!seen[key]) { seen[key] = 1; edges.push([a, b]); }
      }
    });
    return edges;
  }

  // Subdivision (project to unit sphere for geodesic effect)
  function subdivide(V, F) {
    var cache = {}, nV = V.map(function(v){ return v.slice(); }), nF = [];
    function midpoint(i, j) {
      var key = Math.min(i,j) + '_' + Math.max(i,j);
      if (cache[key] !== undefined) return cache[key];
      var a = nV[i], b = nV[j];
      var m = [(a[0]+b[0])/2, (a[1]+b[1])/2, (a[2]+b[2])/2];
      var l = Math.sqrt(m[0]*m[0] + m[1]*m[1] + m[2]*m[2]);
      m[0] /= l; m[1] /= l; m[2] /= l;
      cache[key] = nV.length;
      nV.push(m);
      return cache[key];
    }
    F.forEach(function(f) {
      var a = midpoint(f[0], f[1]);
      var b = midpoint(f[1], f[2]);
      var c = midpoint(f[2], f[0]);
      nF.push([f[0],a,c], [f[1],b,a], [f[2],c,b], [a,b,c]);
    });
    return { v: nV, f: nF };
  }

  // --- Icosahedron ---
  var icoV = normalizeAll([
    [-1,phi,0],[1,phi,0],[-1,-phi,0],[1,-phi,0],
    [0,-1,phi],[0,1,phi],[0,-1,-phi],[0,1,-phi],
    [phi,0,-1],[phi,0,1],[-phi,0,-1],[-phi,0,1]
  ]);
  var icoF = [
    [0,11,5],[0,5,1],[0,1,7],[0,7,10],[0,10,11],
    [1,5,9],[5,11,4],[11,10,2],[10,7,6],[7,1,8],
    [3,9,4],[3,4,2],[3,2,6],[3,6,8],[3,8,9],
    [4,9,5],[2,4,11],[6,2,10],[8,6,7],[9,8,1]
  ];

  // --- Octahedron ---
  var octV = [[1,0,0],[-1,0,0],[0,1,0],[0,-1,0],[0,0,1],[0,0,-1]];
  var octF = [
    [0,2,4],[0,4,3],[0,3,5],[0,5,2],
    [1,2,5],[1,5,3],[1,3,4],[1,4,2]
  ];

  // --- Tetrahedron ---
  var tetV = normalizeAll([
    [1,1,1],[1,-1,-1],[-1,1,-1],[-1,-1,1]
  ]);
  var tetF = [
    [0,1,2],[0,2,3],[0,3,1],[1,3,2]
  ];

  // --- Cube ---
  var cubeV = normalizeAll([
    [-1,-1,-1],[-1,-1,1],[-1,1,-1],[-1,1,1],
    [1,-1,-1],[1,-1,1],[1,1,-1],[1,1,1]
  ]);
  var cubeF = [
    [0,2,3,1],[4,5,7,6],[0,1,5,4],
    [2,6,7,3],[0,4,6,2],[1,3,7,5]
  ];

  // --- Dodecahedron ---
  var invPhi = 1 / phi;
  var dodecV = normalizeAll([
    // cube vertices
    [1,1,1],[1,1,-1],[1,-1,1],[1,-1,-1],
    [-1,1,1],[-1,1,-1],[-1,-1,1],[-1,-1,-1],
    // rectangle vertices
    [0,phi,invPhi],[0,phi,-invPhi],[0,-phi,invPhi],[0,-phi,-invPhi],
    [invPhi,0,phi],[-invPhi,0,phi],[invPhi,0,-phi],[-invPhi,0,-phi],
    [phi,invPhi,0],[phi,-invPhi,0],[-phi,invPhi,0],[-phi,-invPhi,0]
  ]);
  var dodecPentFaces = [
    [0,8,9,1,16],[0,16,17,2,12],[0,12,13,4,8],
    [3,17,16,1,14],[3,14,15,7,11],[3,11,10,2,17],
    [5,9,8,4,18],[5,18,19,7,15],[5,15,14,1,9],
    [6,13,12,2,10],[6,10,11,7,19],[6,19,18,4,13]
  ];
  // Triangulate pentagons (fan from first vertex)
  var dodecF = [];
  dodecPentFaces.forEach(function(face) {
    for (var i = 1; i < face.length - 1; i++) {
      dodecF.push([face[0], face[i], face[i+1]]);
    }
  });

  // --- Shape catalogue ---
  var SHAPES = {};

  function buildShape(v, f) {
    return { v: v, f: f, e: extractEdges(f) };
  }

  SHAPES.ico  = buildShape(icoV, icoF);
  SHAPES.oct  = buildShape(octV, octF);
  SHAPES.tet  = buildShape(tetV, tetF);
  SHAPES.cube = buildShape(cubeV, cubeF);
  SHAPES.dodec = buildShape(dodecV, dodecF);

  // Geodesic shapes built on demand (depends on subdivisions param)
  function buildGeodesic(subdivisions) {
    var s = { v: icoV, f: icoF };
    for (var i = 0; i < subdivisions; i++) {
      s = subdivide(s.v, s.f);
    }
    return buildShape(s.v, s.f);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SPEED PRESETS
     ═══════════════════════════════════════════════════════════════════════ */
  var SPEED_MULT = { slow: 0.4, normal: 1.0, fast: 2.5, insane: 6.0 };

  /* ═══════════════════════════════════════════════════════════════════════
     CONFIG — built from URL params or defaults
     ═══════════════════════════════════════════════════════════════════════ */
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  var CONFIG = {
    background: null,
    cameraZ: 3.5,
    fovFactor: 0.9,
    mouseSmooth: 0.035,
    breathe: 0.04,
    breatheSpeed: 1.5,
    subdivisions: 1,
  };

  // Apply URL params to CONFIG
  if (PARAMS.bg) {
    CONFIG.background = '#' + PARAMS.bg;
  }
  if (PARAMS.fov) {
    CONFIG.fovFactor = clamp(parseFloat(PARAMS.fov), 0.3, 2.0);
  }
  if (PARAMS.camera) {
    CONFIG.cameraZ = clamp(parseFloat(PARAMS.camera), 1.5, 8.0);
  }
  if (PARAMS.mouse) {
    CONFIG.mouseSmooth = clamp(parseFloat(PARAMS.mouse), 0, 1);
  }
  if (PARAMS.breathe) {
    CONFIG.breathe = clamp(parseFloat(PARAMS.breathe), 0, 1);
  }
  if (PARAMS.subdivisions) {
    CONFIG.subdivisions = clamp(parseInt(PARAMS.subdivisions, 10), 0, 3);
  }

  // Build geodesic shapes with current subdivisions
  SHAPES.geo1 = buildGeodesic(CONFIG.subdivisions);
  SHAPES.geo2 = buildGeodesic(Math.min(CONFIG.subdivisions + 1, 3));

  var SHAPE_NAMES = ['ico', 'oct', 'tet', 'cube', 'dodec', 'geo1', 'geo2'];

  /* ═══════════════════════════════════════════════════════════════════════
     SPEED MULTIPLIER
     ═══════════════════════════════════════════════════════════════════════ */
  var speedMult = 1.0;
  if (PARAMS.speed && SPEED_MULT[PARAMS.speed] !== undefined) {
    speedMult = SPEED_MULT[PARAMS.speed];
  }

  /* ═══════════════════════════════════════════════════════════════════════
     RANDOM GENERATOR
     ═══════════════════════════════════════════════════════════════════════ */
  function hslToRgb(h, s, l) {
    h /= 360; s /= 100; l /= 100;
    var r, g, b;
    if (s === 0) {
      r = g = b = l;
    } else {
      function hue2rgb(p, q, t) {
        if (t < 0) t += 1;
        if (t > 1) t -= 1;
        if (t < 1/6) return p + (q - p) * 6 * t;
        if (t < 1/2) return q;
        if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
        return p;
      }
      var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
      var p = 2 * l - q;
      r = hue2rgb(p, q, h + 1/3);
      g = hue2rgb(p, q, h);
      b = hue2rgb(p, q, h - 1/3);
    }
    return Math.round(r*255) + ',' + Math.round(g*255) + ',' + Math.round(b*255);
  }

  function randRange(lo, hi) { return lo + Math.random() * (hi - lo); }
  function randInt(lo, hi) { return Math.floor(randRange(lo, hi + 1)); }
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  function generateRandom() {
    var numLayers = randInt(2, 5);
    var defs = [];
    var baseHue = Math.random() * 360;

    CONFIG.breathe = randRange(0.02, 0.08);
    CONFIG.breatheSpeed = randRange(1.0, 3.0);

    for (var i = 0; i < numLayers; i++) {
      var t = i / (numLayers - 1); // 0 = outer, 1 = inner
      var sc = 1.5 * Math.pow(0.4, t); // log scale from big to small
      var sign = (i % 2 === 0) ? 1 : -1;
      var spd = [
        sign * randRange(0.3, 1.5),
        sign * -randRange(0.2, 1.2),
        sign * randRange(0.1, 0.8)
      ];
      var hue = (baseHue + i * randRange(40, 120)) % 360;
      var col = hslToRgb(hue, randRange(60, 100), randRange(50, 80));
      var lw = 0.4 + t * 1.6;       // thinner outer, thicker inner
      var la = 0.08 + t * 0.4;      // more transparent outer
      var pa = 0.2 + t * 0.6;
      var pr = 1 + t * 3.5;
      var dots = i > 0;             // no dots on outermost
      var shapeName = pick(SHAPE_NAMES);

      defs.push({
        sc: sc, spd: spd, mInf: 0.5 + t * 0.4,
        lw: lw, la: la, col: col,
        pa: pa, pr: pr, dots: dots,
        shape: shapeName
      });
    }
    return defs;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     BUILD LAYER DEFINITIONS
     ═══════════════════════════════════════════════════════════════════════ */
  var layerDefs;
  var activePresetName = 'default';

  if (isRandom) {
    layerDefs = generateRandom();
    activePresetName = 'random';
  } else {
    // Determine number of layers
    var numLayers = 3;
    if (PARAMS.layers) {
      numLayers = clamp(parseInt(PARAMS.layers, 10), 1, 6);
    }

    // Determine preset colors
    var presetName = PARAMS.preset || 'default';
    if (!PRESETS[presetName]) presetName = 'default';
    activePresetName = presetName;
    var presetColors = PRESETS[presetName];

    // Determine shapes per layer
    var shapeNames;
    if (PARAMS.shapes) {
      shapeNames = PARAMS.shapes.split(',');
    } else {
      shapeNames = ['geo1', 'ico', 'oct', 'tet', 'cube', 'dodec'];
    }

    // Default layer style parameters
    var defaultDefs = [
      { sc:1.5, spd:[.5,.35,.2],    mInf:.6, lw:0.6, la:.1,  pa:.25, pr:1.5, dots:false },
      { sc:.8,  spd:[-.8,-.55,-.35],mInf:.7, lw:1.2, la:.25, pa:.5,  pr:2.5, dots:true  },
      { sc:.35, spd:[1.3,.9,.7],    mInf:.9, lw:1.8, la:.45, pa:.7,  pr:4,   dots:true  },
    ];

    layerDefs = [];
    for (var i = 0; i < numLayers; i++) {
      var t = numLayers > 1 ? i / (numLayers - 1) : 0;
      var base = defaultDefs[Math.min(i, defaultDefs.length - 1)];

      // Interpolate properties for layers beyond the 3 defaults
      if (i >= defaultDefs.length) {
        var sc = 1.5 * Math.pow(0.3, t);
        var sign = (i % 2 === 0) ? 1 : -1;
        base = {
          sc: sc,
          spd: [sign * (0.4 + t * 0.9), sign * -(0.3 + t * 0.6), sign * (0.2 + t * 0.5)],
          mInf: 0.5 + t * 0.4,
          lw: 0.4 + t * 1.6,
          la: 0.08 + t * 0.4,
          pa: 0.2 + t * 0.6,
          pr: 1 + t * 3.5,
          dots: i > 0
        };
      }

      layerDefs.push({
        sc: base.sc,
        spd: base.spd.slice(),
        mInf: base.mInf,
        lw: base.lw,
        la: base.la,
        col: presetColors[i % presetColors.length],
        pa: base.pa,
        pr: base.pr,
        dots: base.dots,
        shape: shapeNames[i % shapeNames.length]
      });
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     PREPARE LAYERS — geometry + typed arrays
     ═══════════════════════════════════════════════════════════════════════ */
  var layers = [];
  for (var li = 0; li < layerDefs.length; li++) {
    var def = layerDefs[li];
    var shapeName = def.shape;
    var geo = SHAPES[shapeName] || SHAPES.ico;

    var nv = geo.v.length, ne = geo.e.length;

    // Flatten vertices into typed array
    var fv = new Float64Array(nv * 3);
    for (var i = 0; i < nv; i++) {
      fv[i*3]   = geo.v[i][0];
      fv[i*3+1] = geo.v[i][1];
      fv[i*3+2] = geo.v[i][2];
    }

    // Flatten edges into typed array
    var fe = new Uint16Array(ne * 2);
    for (var i = 0; i < ne; i++) {
      fe[i*2]   = geo.e[i][0];
      fe[i*2+1] = geo.e[i][1];
    }

    layers.push({
      sc: def.sc, spd: def.spd, mInf: def.mInf,
      lw: def.lw, la: def.la, col: def.col,
      pa: def.pa, pr: def.pr, dots: def.dots,
      fv: fv, fe: fe, nv: nv, ne: ne,
      proj: new Float64Array(nv * 2),
    });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     PRE-RENDER GLOW SPRITES (offscreen canvas)
     ═══════════════════════════════════════════════════════════════════════ */
  var DPR = 1;
  function resize() {
    DPR = 1;
    var w = c.clientWidth, h = c.clientHeight;
    var nw = Math.round(w * DPR), nh = Math.round(h * DPR);
    if (c.width !== nw || c.height !== nh) { c.width = nw; c.height = nh; }
  }
  resize();

  function makeGlowSprite(col, alpha, radius) {
    var sz = Math.ceil(radius * 2) | 0;
    if (sz < 2) sz = 2;
    var oc = document.createElement('canvas');
    oc.width = sz; oc.height = sz;
    var ox = oc.getContext('2d');
    var gr = ox.createRadialGradient(sz/2, sz/2, 0, sz/2, sz/2, sz/2);
    gr.addColorStop(0, 'rgba(' + col + ',' + alpha + ')');
    gr.addColorStop(1, 'rgba(' + col + ',0)');
    ox.fillStyle = gr;
    ox.fillRect(0, 0, sz, sz);
    return oc;
  }

  var sprites = [];
  function rebuildSprites() {
    sprites = [];
    for (var i = 0; i < layers.length; i++) {
      var L = layers[i], r = L.pr * DPR * 2.5;
      sprites[i] = makeGlowSprite(L.col, L.pa, r);
    }
  }
  rebuildSprites();

  /* ═══════════════════════════════════════════════════════════════════════
     3D MATH — analytically composed rotation Rz * Rx * Ry
     ═══════════════════════════════════════════════════════════════════════ */
  var R = new Float64Array(9);

  function buildRotation(ay, ax, az) {
    var cy = Math.cos(ay), sy = Math.sin(ay);
    var cx = Math.cos(ax), sx = Math.sin(ax);
    var cz = Math.cos(az), sz = Math.sin(az);
    R[0] = cz*cy + sz*sx*sy;  R[1] = sz*cx;  R[2] = -cz*sy + sz*sx*cy;
    R[3] = -sz*cy + cz*sx*sy; R[4] = cz*cx;  R[5] =  sz*sy + cz*sx*cy;
    R[6] = cx*sy;              R[7] = -sx;    R[8] =  cx*cy;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     MOUSE & TOUCH TRACKING
     ═══════════════════════════════════════════════════════════════════════ */
  var mx = 0, my = 0, smx = 0, smy = 0;
  document.addEventListener('mousemove', function(e) {
    mx = (e.clientX / window.innerWidth  - 0.5) * 2;
    my = (e.clientY / window.innerHeight - 0.5) * 2;
  });
  document.addEventListener('touchmove', function(e) {
    if (e.touches.length > 0) {
      mx = (e.touches[0].clientX / window.innerWidth  - 0.5) * 2;
      my = (e.touches[0].clientY / window.innerHeight - 0.5) * 2;
      e.preventDefault();
    }
  }, { passive: false });

  /* ═══════════════════════════════════════════════════════════════════════
     VISIBILITY & RESIZE
     ═══════════════════════════════════════════════════════════════════════ */
  var needResize = false;
  window.addEventListener('resize', function() { needResize = true; });

  var visible = true;
  var visObs = new IntersectionObserver(function(entries) {
    visible = entries[0].isIntersecting;
  }, { threshold: 0 });
  visObs.observe(c);

  /* ═══════════════════════════════════════════════════════════════════════
     INFO OVERLAY
     ═══════════════════════════════════════════════════════════════════════ */
  var infoEl = document.getElementById('geo3d-info');
  if (infoEl) {
    var shapeSummary = layerDefs.map(function(d) { return d.shape; }).join('+');
    var infoText = layers.length + 'L · ' + activePresetName + ' · ' + shapeSummary;
    infoEl.innerHTML = infoText + '<br><a href="?random" title="Reload with random config">~ random ~</a>';

    // Show for 3s then fade out, reappear on hover
    infoEl.style.opacity = '1';
    var fadeTimer = setTimeout(function() { infoEl.style.opacity = '0'; }, 3000);
    infoEl.addEventListener('mouseenter', function() {
      clearTimeout(fadeTimer);
      infoEl.style.opacity = '1';
    });
    infoEl.addEventListener('mouseleave', function() {
      fadeTimer = setTimeout(function() { infoEl.style.opacity = '0'; }, 1500);
    });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     RENDER LOOP
     ═══════════════════════════════════════════════════════════════════════ */
  var t = 0, lastT = 0;

  function draw(now) {
    requestAnimationFrame(draw);
    if (!visible) return;

    // Timestamp-based animation (frame-rate independent)
    if (!lastT) lastT = now;
    t += (now - lastT) * 0.000004 * speedMult;
    lastT = now;

    if (needResize) { resize(); rebuildSprites(); needResize = false; }

    // Smooth mouse
    smx += (mx - smx) * CONFIG.mouseSmooth;
    smy += (my - smy) * CONFIG.mouseSmooth;

    var W = c.width, H = c.height, hw = W * 0.5, hh = H * 0.5;
    var fov = Math.min(W, H) * CONFIG.fovFactor;
    var camZ = CONFIG.cameraZ;

    ctx.clearRect(0, 0, W, H);

    // Optional background
    if (CONFIG.background) {
      ctx.fillStyle = CONFIG.background;
      ctx.fillRect(0, 0, W, H);
    }

    var pulse = 1 + Math.sin(t * CONFIG.breatheSpeed) * CONFIG.breathe;

    for (var li = 0; li < layers.length; li++) {
      var L = layers[li];
      var fv = L.fv, fe = L.fe, nv = L.nv, ne = L.ne, pr = L.proj;
      var sc = L.sc * (li === 0 ? pulse : 1);

      // Build combined rotation matrix
      buildRotation(
        t * L.spd[0] + smx * L.mInf,
        t * L.spd[1] + smy * L.mInf,
        t * L.spd[2]
      );

      // Transform + project all vertices (inlined, zero allocation)
      for (var i = 0, i3 = 0, i2 = 0; i < nv; i++, i3 += 3, i2 += 2) {
        var vx = fv[i3], vy = fv[i3+1], vz = fv[i3+2];
        var tz = (R[6]*vx + R[7]*vy + R[8]*vz) * sc - camZ;
        var f  = fov / (-tz);
        pr[i2]   = hw + (R[0]*vx + R[1]*vy + R[2]*vz) * sc * f;
        pr[i2+1] = hh - (R[3]*vx + R[4]*vy + R[5]*vz) * sc * f;
      }

      // Draw edges (single batched path)
      ctx.lineWidth = L.lw * DPR;
      ctx.strokeStyle = 'rgba(' + L.col + ',' + L.la + ')';
      ctx.beginPath();
      for (var i = 0, i2 = 0; i < ne; i++, i2 += 2) {
        var ai = fe[i2] << 1, bi = fe[i2+1] << 1;
        ctx.moveTo(pr[ai], pr[ai+1]);
        ctx.lineTo(pr[bi], pr[bi+1]);
      }
      ctx.stroke();

      // Draw vertex glow sprites
      if (L.dots) {
        var spr = sprites[li], ss = spr.width, sh = ss * 0.5;
        for (var i = 0, i2 = 0; i < nv; i++, i2 += 2) {
          ctx.drawImage(spr, pr[i2] - sh, pr[i2+1] - sh);
        }
      }
    }
  }

  requestAnimationFrame(draw);
})();
