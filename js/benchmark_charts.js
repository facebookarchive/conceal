var cipherLabels = ["Java", "Bouncycastle", "Conceal"];
var macLabels = ["Java", "Conceal"];
var commonOptions = {
  scaleLabel: "<%=value%>ms",
  scaleShowLabels : true
}

function createBenchmarkData(data, labels) {
  return {
    labels : labels,
    datasets : [
      {
        fillColor : "rgba(151,187,205,0.5)",
        strokeColor : "rgba(151,187,205,1)",
        data : data
      },
    ]
  }
}

var canvasIds = {};

function sizeCanvas(canvas) {
  var width = window.getComputedStyle(canvas.parentElement).width;
  canvas.width = parseInt(width) - 7;
  canvas.height = 175;
}

function drawChart(name, data) {
  var canvas = document.getElementById(name);
  sizeCanvas(canvas);
  var ctx = canvas.getContext("2d");
  new Chart(ctx).Bar(data, commonOptions);
}

function drawReadBenchmarks(readBenchmarkId) {
  var data = createBenchmarkData([261, 233, 15], cipherLabels);
  canvasIds["read"] = readBenchmarkId;
  drawChart(readBenchmarkId, data);
}

function drawWriteBenchmarks(writeBenchmarkId) {
  var data = createBenchmarkData([143, 219, 13], cipherLabels);
  canvasIds["write"] = writeBenchmarkId;
  drawChart(writeBenchmarkId, data);
}

function drawMacBenchmarks(macBenchmarkId) {
  var data = createBenchmarkData([56, 4], macLabels);
  canvasIds["mac"] = macBenchmarkId;
  drawChart(macBenchmarkId, data);
}

window.onresize = function() {  
  var readId = canvasIds["read"];
  if (!(readId == undefined)) {
    drawReadBenchmarks(readId);
  }
  var writeId = canvasIds["write"];
  if (!(writeId == undefined)) {
    drawWriteBenchmarks(writeId);
  }
  var macId = canvasIds["mac"];
  if (!(macId == undefined)) {
    drawMacBenchmarks(macId);
  }
}
