// HNG Chart.js theme — applied globally before any charts initialize
const HNG_CHART_THEME = {
  primary:   '#00e639',
  secondary: '#98cbff',
  error:     '#ffb4ab',
  muted:     '#3b4b37',
  text:      '#84967e',

  trafficDataset: (data) => ({
    data,
    borderColor: '#00e639',
    borderWidth: 2,
    backgroundColor: (ctx) => {
      const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height);
      g.addColorStop(0, 'rgba(0,230,57,0.2)');
      g.addColorStop(1, 'rgba(0,230,57,0)');
      return g;
    },
    fill: true,
    tension: 0.4,
    pointRadius: 0,
    pointHoverRadius: 4,
    pointHoverBackgroundColor: '#00e639',
  }),

  secondaryDataset: (data) => ({
    data,
    borderColor: '#98cbff',
    borderWidth: 1.5,
    backgroundColor: 'rgba(152,203,255,0.05)',
    fill: true,
    tension: 0.4,
    pointRadius: 0,
  }),
};

if (typeof Chart !== 'undefined') {
  Chart.defaults.color          = '#84967e';
  Chart.defaults.font.family    = "'JetBrains Mono', monospace";
  Chart.defaults.font.size      = 11;
  Chart.defaults.borderColor    = '#3b4b37';
  Chart.defaults.backgroundColor = '#00e639';

  if (Chart.defaults.plugins) {
    Chart.defaults.plugins.legend = { display: false };
    Chart.defaults.plugins.tooltip = {
      backgroundColor: '#0e0e0e',
      borderColor:     '#3b4b37',
      borderWidth:     1,
      titleColor:      '#00e639',
      bodyColor:       '#e5e2e1',
      titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
      bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
      padding:   12,
    };
  }
}
