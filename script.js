// Interactivo - Laboratorio simulado
const fileInput = document.getElementById('fileInput');
const btnHash = document.getElementById('btnHash');
const btnStrings = document.getElementById('btnStrings');
const btnStatic = document.getElementById('btnStatic');
const btnDynamic = document.getElementById('btnDynamic');
const shaOutput = document.getElementById('shaOutput');
const metaOutput = document.getElementById('metaOutput');
const stringsOutput = document.getElementById('stringsOutput');
const importsOutput = document.getElementById('importsOutput');
const iocsOutput = document.getElementById('iocsOutput');
const btnRunSim = document.getElementById('btnRunSim');
const trafficChart = document.getElementById('trafficChart');
const processList = document.getElementById('processList');
const btnReport = document.getElementById('btnReport');
let currentFile = null;
let currentArrayBuffer = null;

fileInput.addEventListener('change', (e)=>{
  const f = e.target.files[0];
  currentFile = f || null;
  shaOutput.textContent = '';
  stringsOutput.textContent = '';
  metaOutput.textContent = f ? `${f.name} — ${f.type || 'desconocido'} — ${f.size} bytes` : '';
  importsOutput.innerHTML = '';
  iocsOutput.innerHTML = '';
  processList.innerHTML = '';
  clearChart();
  if(f){
    const reader = new FileReader();
    reader.onload = ()=> { currentArrayBuffer = reader.result; };
    reader.readAsArrayBuffer(f);
  }
});

async function sha256OfBuffer(buffer){
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  const arr = Array.from(new Uint8Array(hash));
  return arr.map(b=>b.toString(16).padStart(2,'0')).join('');
}

btnHash.addEventListener('click', async ()=>{
  if(!currentFile){ alert('Carga primero un archivo.'); return; }
  try{
    const hash = await sha256OfBuffer(currentArrayBuffer);
    shaOutput.textContent = hash;
  }catch(e){ shaOutput.textContent = 'Error calculando hash.'; }
});

btnStrings.addEventListener('click', ()=>{
  if(!currentArrayBuffer){ alert('Carga primero un archivo.'); return; }
  const txt = extractStrings(new Uint8Array(currentArrayBuffer), 4);
  stringsOutput.textContent = txt.slice(0,30).join('\n');
});

function extractStrings(bytes, minLen=4){
  let s = '';
  const out = [];
  for(let i=0;i<bytes.length;i++){
    const c = bytes[i];
    if(c>=32 && c<=126){ s+=String.fromCharCode(c); } else { if(s.length>=minLen){ out.push(s); } s=''; }
  }
  if(s.length>=minLen) out.push(s);
  return out;
}

btnStatic.addEventListener('click', async ()=>{
  if(!currentArrayBuffer){ alert('Carga primero un archivo.'); return; }
  const hash = await sha256OfBuffer(currentArrayBuffer);
  shaOutput.textContent = hash;

  const seed = hash.slice(0,8);
  const libs = simulateImports(seed);
  importsOutput.innerHTML = libs.map(x=>`<li>${x}</li>`).join('');

  const iocs = simulateIOCs(seed);
  iocsOutput.innerHTML = iocs.map(x=>`<li>${x}</li>`).join('');

  metaOutput.textContent = `Nombre: ${currentFile.name} — Tipo: ${currentFile.type||'desconocido'} — Tamaño: ${currentFile.size} bytes`;
});

btnDynamic.addEventListener('click', ()=>{
  alert('Aquí verás simulaciones seguras del análisis dinámico.');
});

btnRunSim.addEventListener('click', async ()=>{
  if(!currentArrayBuffer){ alert('Carga un archivo para simular.'); return; }
  const hash = await sha256OfBuffer(currentArrayBuffer);
  runSimulation(hash);
});

function simulateImports(seed){
  const pool = ['kernel32.dll','user32.dll','ws2_32.dll','ntdll.dll','advapi32.dll','bcrypt.dll','winhttp.dll','shell32.dll'];
  const funcs = ['CreateProcess','InternetConnect','URLDownloadToFile','VirtualAlloc','WriteFile','OpenProcess','GetProcAddress','LoadLibraryA'];
  const n = (parseInt(seed.slice(0,6),16) % 5) + 3;
  const out = [];
  for(let i=0;i<n;i++){
    out.push(pool[(i+parseInt(seed.slice(i%seed.length, (i%seed.length)+2),16))%pool.length] + ' -> ' + funcs[i%funcs.length]);
  }
  return out;
}

function simulateIOCs(seed){
  const ips = ['192.168.10.23','104.21.34.8','93.184.216.34','45.77.23.12','172.217.6.142'];
  const doms = ['bad-example.com','tracking.example.net','updater.service','cdn.malicious'];
  const out = [];
  out.push('IP sospechosa: ' + ips[parseInt(seed.slice(0,2),16)%ips.length]);
  out.push('Dominio: ' + doms[parseInt(seed.slice(2,4),16)%doms.length]);
  out.push('Puerto: ' + (3000 + (parseInt(seed.slice(4,6),16)%2000)));
  return out;
}

function runSimulation(seed){
  const numPoints = 12;
  const values = [];
  for(let i=0;i<numPoints;i++){
    const v = (parseInt(seed.slice((i%seed.length), (i%seed.length)+4),16) % 80) + 10;
    values.push(v);
  }
  drawChart(values);

  const procs = [
    'svchost.exe (networking)',
    'updater.exe (sospechoso)',
    'chrome.exe (spawned)',
    'powershell.exe (script)',
    'evil_child.exe (in-memory)'
  ];
  processList.innerHTML = procs.map(p=>`<li>${p}</li>`).join('');
}

function drawChart(vals){
  const svg = trafficChart;
  svg.innerHTML = '';
  const w = 600, h = 160, pad=20;
  const max = Math.max(...vals);
  const step = (w-2*pad)/(vals.length-1);

  const points = vals.map((v,i)=> (pad + i*step) + ',' + (h-pad - ((v/max)*(h-2*pad))) ).join(' ');
  const poly = document.createElementNS('http://www.w3.org/2000/svg','polyline');
  poly.setAttribute('points', points);
  poly.setAttribute('fill','none');
  poly.setAttribute('stroke','#6ee7b7');
  poly.setAttribute('stroke-width','3');
  svg.appendChild(poly);

  vals.forEach((v,i)=>{
    const cx = pad + i*step;
    const cy = h-pad - ((v/max)*(h-2*pad));
    const c = document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',cx); c.setAttribute('cy',cy); c.setAttribute('r',4);
    c.setAttribute('fill','#60a5fa');
    svg.appendChild(c);
  });
}

function clearChart(){ trafficChart.innerHTML = ''; }

btnReport.addEventListener('click', async ()=>{
  const title = document.createElement('div');
  title.innerHTML = `<h2>Informe técnico — CyberLab</h2><p>Archivo: ${currentFile?currentFile.name:'(ninguno)'}</p>`;

  const body = document.createElement('div');
  body.innerHTML = '<h3>SHA-256</h3><pre>' + (shaOutput.textContent || '(sin calcular)') + '</pre>' +
                   '<h3>Metadata</h3><pre>' + (metaOutput.textContent || '') + '</pre>' +
                   '<h3>Strings (primeras 30)</h3><pre>' + (stringsOutput.textContent || '') + '</pre>' +
                   '<h3>Imports detectados</h3><pre>' + (Array.from(importsOutput.querySelectorAll('li')).map(x=>x.textContent).join('\n') || '') + '</pre>' +
                   '<h3>IoCs</h3><pre>' + (Array.from(iocsOutput.querySelectorAll('li')).map(x=>x.textContent).join('\n') || '') + '</pre>';

  const win = window.open('', '_blank', 'width=800,height=900');
  win.document.write('<html><head><title>Informe</title><style>body{font-family:Arial;color:#0b1220;padding:20px} pre{background:#f3f4f6;padding:12px;border-radius:6px}</style></head><body>');
  win.document.write(title.outerHTML + body.outerHTML);
  win.document.write('</body></html>');
  win.document.close();
});
