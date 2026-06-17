document.addEventListener('DOMContentLoaded', () => {
    // Generate colorful tone-down colors spread across the spectrum
    const generateColors = (count) => {
        const colors = [];
        for (let i = 0; i < count; i++) {
            const hue = (i * (360 / Math.max(1, count))) % 360;
            colors.push(`hsl(${hue}, 50%, 60%)`);
        }
        return colors;
    };

    // Application State
    const state = {
        portfolios: {},
        currentPortfolio: 'Default',
        assets: [],
        frequency: 'daily',
        dayOfWeek: '1',
        columns: [
            { id: 'status', label: 'Status', width: '60px' },
            { id: 'name', label: 'Asset', width: '100px' },
            { id: 'type', label: 'Type', width: '120px' },
            { id: 'invested', label: 'Invested', width: '70px' },
            { id: 'percent', label: 'Percent (%)', width: '100px' },
            { id: 'val', label: 'Value ($)', width: '90px' },
            { id: 'start', label: 'Start Date', width: '150px' },
            { id: 'end', label: 'End Date', width: '150px' },
            { id: 'delete', label: '🗑️', width: '50px' }
        ],
        colors: [],
        chartOpen: false,
        myChart: null,
        timelineOpen: false,
        pieChart: null,
        timelineChart: null,
        timelineItems: null,
        sortableInst: null
    };

    // Cached DOM Elements
    const els = {
        portfolioSelect: document.getElementById('portfolio-select'),
        btnNewPortfolio: document.getElementById('btn-new-portfolio'),
        btnSavePortfolio: document.getElementById('btn-save-portfolio'),
        btnDeletePortfolio: document.getElementById('btn-delete-portfolio'),
        globalTotal: document.getElementById('global-total'),
        investFrequency: document.getElementById('invest-frequency'),
        dayOfWeekGroup: document.getElementById('day-of-week-group'),
        investDay: document.getElementById('invest-day'),
        allocationSum: document.getElementById('allocation-sum'),
        masterStart: document.getElementById('master-start'),
        masterEnd: document.getElementById('master-end'),
        targetCheckboxes: document.getElementById('target-checkboxes'),
        btnApplyDates: document.getElementById('btn-apply-dates'),
        assetHeaders: document.getElementById('asset-headers'),
        assetList: document.getElementById('asset-list'),
        btnAddRow: document.getElementById('btn-add-row'),
        btnToggleTimeline: document.getElementById('btn-toggle-timeline'),
        timelineWrapper: document.getElementById('timeline-wrapper'),
        timelineContainer: document.getElementById('timeline-container'),
        btnRunSim: document.getElementById('btn-run-sim'),
        graphDropdown: document.getElementById('graph-dropdown'),
        periodTotalLabel: document.getElementById('period-total-label'),
        chartCtx: document.getElementById('dcaChart').getContext('2d'),
        pieCtx: document.getElementById('allocationPieChart').getContext('2d'),
        presets: document.querySelectorAll('.btn-preset')
    };

    // --- Utilities ---
    const formatDateStr = (dateObj) => {
        const d = new Date(dateObj);
        return d.toISOString().split('T')[0];
    };

    const snapDateToDay = (dateStr, targetDayOfWeek) => {
        if (!dateStr) return dateStr;
        const d = new Date(dateStr + 'T00:00:00Z');
        const target = parseInt(targetDayOfWeek, 10);
        const currentDay = d.getUTCDay();
        
        if (currentDay !== target) {
            let shift = target - currentDay;
            // Shift to closest target day
            if (shift < -3) shift += 7;
            if (shift > 3) shift -= 7;
            d.setUTCDate(d.getUTCDate() + shift);
        }
        return formatDateStr(d);
    };

    const getDeploymentEvents = (startStr, endStr, type, frequency, targetDayOfWeek) => {
        if (!startStr || !endStr) return 0;
        const start = new Date(startStr + 'T00:00:00Z');
        const end = new Date(endStr + 'T00:00:00Z');
        if (start > end) return 0;

        let events = 0;
        let curr = new Date(start);

        if (frequency === 'daily') {
            while (curr <= end) {
                const day = curr.getUTCDay();
                if (type === 'crypto' || (day !== 0 && day !== 6)) {
                    events++;
                }
                curr.setUTCDate(curr.getUTCDate() + 1);
            }
        } else {
            const dayTarget = parseInt(targetDayOfWeek, 10);
            while (curr <= end) {
                if (curr.getUTCDay() === dayTarget) {
                    events++;
                    if (frequency === 'biweekly') {
                        curr.setUTCDate(curr.getUTCDate() + 14);
                    } else {
                        curr.setUTCDate(curr.getUTCDate() + 7);
                    }
                } else {
                    curr.setUTCDate(curr.getUTCDate() + 1);
                }
            }
        }
        return events;
    };

    // --- Portfolio Management ---
    const loadPortfolios = () => {
        const saved = localStorage.getItem('dca_portfolios');
        if (saved) {
            state.portfolios = JSON.parse(saved);
        } else {
            const today = new Date();
            const eoy = new Date(today.getFullYear(), 11, 31);
            const todayStr = formatDateStr(today);
            const eoyStr = formatDateStr(eoy);

            state.portfolios = {
                'Default': { 
                    assets: [
                        { id: 1, name: 'BTC', type: 'crypto', percent: 20, val: 2000, invested: false, start: todayStr, end: eoyStr },
                        { id: 2, name: 'VEQT', type: 'trad', percent: 80, val: 8000, invested: false, start: todayStr, end: eoyStr }
                    ], 
                    total: '10000',
                    columns: JSON.parse(JSON.stringify(state.columns)),
                    frequency: 'daily',
                    dayOfWeek: '1'
                }
            };
            localStorage.setItem('dca_portfolios', JSON.stringify(state.portfolios));
        }
        updatePortfolioSelect();
        applyPortfolio(state.currentPortfolio);
    };

    const updatePortfolioSelect = () => {
        els.portfolioSelect.innerHTML = '';
        Object.keys(state.portfolios).forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.innerText = name;
            if (name === state.currentPortfolio) opt.selected = true;
            els.portfolioSelect.appendChild(opt);
        });
    };

    const applyPortfolio = (name) => {
        if (!state.portfolios[name]) return;
        state.currentPortfolio = name;
        els.portfolioSelect.value = name;
        state.assets = JSON.parse(JSON.stringify(state.portfolios[name].assets || []));
        els.globalTotal.value = state.portfolios[name].total || '0';
        
        if (state.portfolios[name].columns) {
            state.columns = JSON.parse(JSON.stringify(state.portfolios[name].columns));
        }
        
        state.frequency = state.portfolios[name].frequency || 'daily';
        state.dayOfWeek = state.portfolios[name].dayOfWeek || '1';
        
        els.investFrequency.value = state.frequency;
        els.investDay.value = state.dayOfWeek;
        els.dayOfWeekGroup.style.display = state.frequency === 'daily' ? 'none' : 'flex';

        initDatesIfEmpty();
        state.colors = generateColors(state.assets.length);
        renderHeaders();
        renderRows();
    };

    const savePortfolio = (name) => {
        state.portfolios[name] = {
            assets: JSON.parse(JSON.stringify(state.assets)),
            total: els.globalTotal.value,
            columns: JSON.parse(JSON.stringify(state.columns)),
            frequency: state.frequency,
            dayOfWeek: state.dayOfWeek
        };
        localStorage.setItem('dca_portfolios', JSON.stringify(state.portfolios));
        state.currentPortfolio = name;
        updatePortfolioSelect();
    };

    // --- Init & Core Logic ---
    const initDatesIfEmpty = () => {
        const today = new Date();
        const defaultEnd = new Date();
        defaultEnd.setDate(today.getDate() + 30);
        
        let hasEmpty = false;
        state.assets.forEach(a => {
            if (!a.start && !a.end && !a.invested) hasEmpty = true;
        });

        if (hasEmpty && state.assets.length > 0) {
            els.masterStart.value = formatDateStr(today);
            els.masterEnd.value = formatDateStr(defaultEnd);
        }
    };

    const showValidationTooltip = (el, message) => {
        const existing = document.getElementById('validation-tooltip');
        if (existing) existing.remove();

        const tooltip = document.createElement('div');
        tooltip.id = 'validation-tooltip';
        tooltip.className = 'validation-tooltip';
        tooltip.innerHTML = `<span>⚠️</span> ${message}`;
        
        document.body.appendChild(tooltip);

        const rect = el.getBoundingClientRect();
        tooltip.style.top = `${rect.top + window.scrollY - 45}px`;
        tooltip.style.left = `${rect.left + window.scrollX}px`;

        requestAnimationFrame(() => tooltip.classList.add('visible'));

        el.focus();

        const removeTooltip = () => {
            tooltip.classList.remove('visible');
            setTimeout(() => { if (tooltip.parentNode) tooltip.remove(); }, 300);
            el.removeEventListener('input', removeTooltip);
            window.removeEventListener('scroll', removeTooltip);
        };

        el.addEventListener('input', removeTooltip);
        window.addEventListener('scroll', removeTooltip);
        setTimeout(removeTooltip, 5000); 
    };

    const getGridTemplateColumns = () => {
        return state.columns.map(c => c.width).join(' ');
    };

    const renderHeaders = () => {
        els.assetHeaders.innerHTML = '';
        els.assetHeaders.style.gridTemplateColumns = getGridTemplateColumns();

        state.columns.forEach((col, index) => {
            const headerCell = document.createElement('div');
            headerCell.className = 'header-cell';
            headerCell.dataset.id = col.id;
            headerCell.dataset.index = index;
            headerCell.style.textAlign = (col.id === 'status' || col.id === 'delete' || col.id === 'invested') ? 'center' : 'left';
            headerCell.innerHTML = `<span>${col.label}</span>`;
            els.assetHeaders.appendChild(headerCell);
        });

        if (!state.sortableInst) {
            state.sortableInst = Sortable.create(els.assetHeaders, {
                animation: 150,
                ghostClass: 'sortable-ghost',
                dragClass: 'sortable-drag',
                onEnd: (evt) => {
                    const oldIndex = evt.oldIndex;
                    const newIndex = evt.newIndex;
                    const movedItem = state.columns.splice(oldIndex, 1)[0];
                    state.columns.splice(newIndex, 0, movedItem);
                    renderHeaders();
                    renderRows();
                }
            });
        }
    };

    const renderRows = () => {
        els.assetList.innerHTML = '';
        els.targetCheckboxes.innerHTML = `
            <label class="checkbox-group">
                <input type="checkbox" id="check-all" checked> All
            </label>
        `;
        
        let totalPct = 0;
        const gridTemplate = getGridTemplateColumns();
        state.colors = generateColors(state.assets.length);

        state.assets.forEach((asset, index) => {
            totalPct += parseFloat(asset.percent) || 0;
            
            let isComplete = false;
            if (asset.invested) {
                isComplete = asset.name && asset.percent > 0;
            } else {
                isComplete = asset.start && asset.end && asset.name && asset.percent > 0;
            }
            const statusIcon = isComplete ? `<div class="status-check valid" title="Valid">✅</div>` : `<div class="status-check invalid" title="Pending Info">⏳</div>`;

            const row = document.createElement('div');
            row.className = `asset-row ${asset.invested ? 'invested-row' : ''}`;
            row.style.gridTemplateColumns = gridTemplate;
            
            let rowHTML = '';
            
            state.columns.forEach(col => {
                switch (col.id) {
                    case 'status':
                        rowHTML += statusIcon;
                        break;
                    case 'name':
                        rowHTML += `<input type="text" class="input-name" data-index="${index}" value="${asset.name || ''}">`;
                        break;
                    case 'type':
                        rowHTML += `
                            <select class="input-type" data-index="${index}">
                                <option value="trad" ${asset.type === 'trad' ? 'selected' : ''}>Trad (M-F)</option>
                                <option value="crypto" ${asset.type === 'crypto' ? 'selected' : ''}>Crypto (24/7)</option>
                            </select>`;
                        break;
                    case 'invested':
                        rowHTML += `<div style="text-align: center;"><input type="checkbox" class="input-invested" data-index="${index}" ${asset.invested ? 'checked' : ''}></div>`;
                        break;
                    case 'percent':
                        rowHTML += `<input type="number" step="0.01" class="input-percent" data-index="${index}" value="${asset.percent || 0}">`;
                        break;
                    case 'val':
                        rowHTML += `<input type="number" step="1" class="input-val" data-index="${index}" value="${asset.val || 0}">`;
                        break;
                    case 'start':
                        rowHTML += `<input type="date" class="input-start" data-index="${index}" value="${asset.start || ''}">`;
                        break;
                    case 'end':
                        rowHTML += `<input type="date" class="input-end" data-index="${index}" value="${asset.end || ''}">`;
                        break;
                    case 'delete':
                        rowHTML += `<div style="text-align: center;"><button class="btn-delete" data-index="${index}">×</button></div>`;
                        break;
                }
            });

            row.innerHTML = rowHTML;
            els.assetList.appendChild(row);

            if (!asset.invested) {
                els.targetCheckboxes.innerHTML += `
                    <label class="checkbox-group">
                        <input type="checkbox" class="asset-target-cb" data-index="${index}" checked> ${asset.name || 'Unnamed'}
                    </label>
                `;
            }
        });

        els.allocationSum.innerText = `${totalPct.toFixed(2)}%`;
        els.allocationSum.style.color = Math.abs(totalPct - 100) > 0.1 ? 'var(--danger)' : 'var(--gold-accent)';

        if (state.chartOpen) updateChart();
        updatePieChart();
        if (state.timelineChart) syncTimelineData();
    };

    const updatePieChart = () => {
        // Create sorted copy of assets for pie chart based on value (descending)
        const sortedAssets = [...state.assets].sort((a, b) => (parseFloat(b.val) || 0) - (parseFloat(a.val) || 0));
        
        const labels = sortedAssets.map(a => a.name || 'Unnamed');
        const data = sortedAssets.map(a => parseFloat(a.percent) || 0);
        const sortedColors = generateColors(sortedAssets.length);

        if (state.pieChart) {
            state.pieChart.data.labels = labels;
            state.pieChart.data.datasets[0].data = data;
            state.pieChart.data.datasets[0].backgroundColor = sortedColors;
            state.pieChart.update();
        } else {
            Chart.defaults.color = '#9e9e9e';
            state.pieChart = new Chart(els.pieCtx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{ data: data, backgroundColor: sortedColors, borderWidth: 1, borderColor: '#1a1a1a' }]
                },
                options: {
                    responsive: true,
                    plugins: { 
                        legend: { position: 'bottom', labels: { boxWidth: 12, padding: 15 } },
                        tooltip: { callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.raw}%` } }
                    },
                    cutout: '65%'
                }
            });
        }
    };

    const syncTimelineData = () => {
        if (!state.timelineItems) return;
        const currentData = [];
        state.assets.forEach((a, i) => {
            if (a.invested) return;
            currentData.push({
                id: i,
                content: a.name || 'Unnamed',
                start: a.start ? a.start + 'T00:00:00' : formatDateStr(new Date()) + 'T00:00:00',
                end: a.end ? a.end + 'T23:59:59' : formatDateStr(new Date()) + 'T23:59:59'
            });
        });
        
        state.timelineItems.clear();
        state.timelineItems.add(currentData);
    };

    const initTimelineChart = () => {
        if (state.timelineChart) return;
        
        state.timelineItems = new vis.DataSet();
        syncTimelineData();

        const options = {
            editable: { updateTime: true, updateGroup: false, add: false, remove: false },
            margin: { item: 10, axis: 5 },
            orientation: 'top',
            onMove: (item, callback) => {
                const idx = item.id;
                if (state.assets[idx] && !state.assets[idx].invested) {
                    let newStart = formatDateStr(item.start);
                    let newEnd = formatDateStr(item.end);
                    if (state.frequency !== 'daily') {
                        newStart = snapDateToDay(newStart, state.dayOfWeek);
                        newEnd = snapDateToDay(newEnd, state.dayOfWeek);
                    }
                    state.assets[idx].start = newStart;
                    state.assets[idx].end = newEnd;
                    renderRows();
                }
                callback(item);
            }
        };

        state.timelineChart = new vis.Timeline(els.timelineContainer, state.timelineItems, options);
    };

    const updateChart = () => {
        let labels = [], dataPeriod = [], bgColors = [], totalPeriodOutflow = 0;

        state.assets.forEach((a, i) => {
            if (a.invested) return;
            const events = getDeploymentEvents(a.start, a.end, a.type, state.frequency, state.dayOfWeek);
            const periodAmt = events > 0 ? (parseFloat(a.val) / events) : 0;
            labels.push(a.name || 'Unnamed');
            dataPeriod.push(periodAmt.toFixed(2));
            bgColors.push(state.colors[i % state.colors.length]);
            totalPeriodOutflow += periodAmt;
        });

        els.periodTotalLabel.innerText = `Total per Deployment: $${totalPeriodOutflow.toFixed(2)}`;

        if (state.myChart) {
            state.myChart.data.labels = labels;
            state.myChart.data.datasets[0].data = dataPeriod;
            state.myChart.data.datasets[0].backgroundColor = bgColors;
            
            // Update tooltip dynamically based on new sum
            state.myChart.options.plugins.tooltip.callbacks.label = function(context) { 
                const val = context.parsed.y;
                const pct = totalPeriodOutflow > 0 ? ((val / totalPeriodOutflow) * 100).toFixed(2) : 0;
                return `$${val.toFixed(2)} (${pct}% of period total)`; 
            };
            
            state.myChart.update();
        } else {
            Chart.defaults.color = '#9e9e9e';
            Chart.defaults.borderColor = '#333';
            state.myChart = new Chart(els.chartCtx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{ label: 'Deployment Amount ($)', data: dataPeriod, backgroundColor: bgColors, borderWidth: 1, borderColor: '#121212' }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { 
                        legend: { display: false }, 
                        tooltip: { 
                            callbacks: { 
                                label: function(context) { 
                                    const val = context.parsed.y;
                                    const pct = totalPeriodOutflow > 0 ? ((val / totalPeriodOutflow) * 100).toFixed(2) : 0;
                                    return `$${val.toFixed(2)} (${pct}% of period total)`; 
                                } 
                            } 
                        } 
                    },
                    scales: { y: { beginAtZero: true, title: { display: true, text: 'Dollars ($)' } } }
                }
            });
        }
    };

    // --- Event Listeners and Bindings ---
    const bindEvents = () => {
        // Portfolio Management
        els.portfolioSelect.addEventListener('change', (e) => {
            applyPortfolio(e.target.value);
        });

        els.btnNewPortfolio.addEventListener('click', () => {
            const name = prompt("Enter a name for the new portfolio:");
            if (name && name.trim() !== '') {
                state.currentPortfolio = name.trim();
                const todayStr = formatDateStr(new Date());
                const eoyStr = formatDateStr(new Date(new Date().getFullYear(), 11, 31));
                
                state.assets = [
                    { id: Date.now(), name: 'BTC', type: 'crypto', percent: 20, val: 2000, invested: false, start: todayStr, end: eoyStr },
                    { id: Date.now()+1, name: 'VEQT', type: 'trad', percent: 80, val: 8000, invested: false, start: todayStr, end: eoyStr }
                ];
                els.globalTotal.value = '10000';
                savePortfolio(state.currentPortfolio);
                applyPortfolio(state.currentPortfolio);
            }
        });

        els.btnSavePortfolio.addEventListener('click', () => {
            if (state.currentPortfolio === 'Default') {
                const name = prompt("Save as new portfolio name:", "My Portfolio");
                if (name && name.trim() !== '') {
                    savePortfolio(name.trim());
                }
            } else {
                savePortfolio(state.currentPortfolio);
                alert("Portfolio saved!");
            }
        });

        els.btnDeletePortfolio.addEventListener('click', () => {
            if (state.currentPortfolio === 'Default') {
                alert("Cannot delete the Default portfolio.");
                return;
            }
            if (confirm(`Are you sure you want to delete '${state.currentPortfolio}'?`)) {
                delete state.portfolios[state.currentPortfolio];
                localStorage.setItem('dca_portfolios', JSON.stringify(state.portfolios));
                applyPortfolio('Default');
            }
        });

        // Global Total & Frequency
        els.globalTotal.addEventListener('input', (e) => {
            const total = parseFloat(e.target.value) || 0;
            state.assets.forEach(a => { a.val = (total * (a.percent / 100)).toFixed(2); });
            renderRows();
        });

        els.investFrequency.addEventListener('change', (e) => {
            state.frequency = e.target.value;
            els.dayOfWeekGroup.style.display = state.frequency === 'daily' ? 'none' : 'flex';
            if (state.frequency !== 'daily') {
                state.assets.forEach(a => {
                    if (a.start) a.start = snapDateToDay(a.start, state.dayOfWeek);
                    if (a.end) a.end = snapDateToDay(a.end, state.dayOfWeek);
                });
            }
            renderRows();
        });

        els.investDay.addEventListener('change', (e) => {
            state.dayOfWeek = e.target.value;
            if (state.frequency !== 'daily') {
                state.assets.forEach(a => {
                    if (a.start) a.start = snapDateToDay(a.start, state.dayOfWeek);
                    if (a.end) a.end = snapDateToDay(a.end, state.dayOfWeek);
                });
                renderRows();
            }
        });

        // Dynamic Form Asset Input Delegation
        els.assetList.addEventListener('change', (e) => {
            const index = parseInt(e.target.dataset.index, 10);
            if (isNaN(index) || !state.assets[index]) return;

            const total = parseFloat(els.globalTotal.value) || 0;
            
            if (e.target.classList.contains('input-name')) {
                state.assets[index].name = e.target.value;
            } else if (e.target.classList.contains('input-type')) {
                state.assets[index].type = e.target.value;
            } else if (e.target.classList.contains('input-percent')) {
                state.assets[index].percent = parseFloat(e.target.value) || 0;
                state.assets[index].val = (total * (state.assets[index].percent / 100)).toFixed(2);
            } else if (e.target.classList.contains('input-val')) {
                state.assets[index].val = parseFloat(e.target.value) || 0;
                
                let newTotal = state.assets.reduce((sum, a) => sum + (parseFloat(a.val) || 0), 0);
                els.globalTotal.value = newTotal.toFixed(2);
                
                if (newTotal > 0) {
                    state.assets.forEach(a => {
                        a.percent = (((parseFloat(a.val) || 0) / newTotal) * 100).toFixed(2);
                    });
                } else {
                    state.assets.forEach(a => { a.percent = 0; });
                }
            } else if (e.target.classList.contains('input-start')) {
                let d = e.target.value;
                if (state.frequency !== 'daily') d = snapDateToDay(d, state.dayOfWeek);
                state.assets[index].start = d;
                e.target.value = d; // update dom
            } else if (e.target.classList.contains('input-end')) {
                let d = e.target.value;
                if (state.frequency !== 'daily') d = snapDateToDay(d, state.dayOfWeek);
                state.assets[index].end = d;
                e.target.value = d; // update dom
            } else if (e.target.classList.contains('input-invested')) {
                state.assets[index].invested = e.target.checked;
            }
            renderRows();
        });

        els.assetList.addEventListener('click', (e) => {
            if (e.target.classList.contains('btn-delete')) {
                const index = parseInt(e.target.dataset.index, 10);
                if (!isNaN(index)) {
                    state.assets.splice(index, 1);
                    renderRows();
                }
            }
        });

        // Preset Management
        els.presets.forEach(btn => {
            if (btn.id === 'btn-new-portfolio' || btn.id === 'btn-save-portfolio') return;
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.preset-row .btn-preset').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');

                const val = e.target.dataset.preset;
                if (val === 'custom') return;

                const start = new Date();
                const end = new Date();

                if (val === 'eoy') {
                    end.setFullYear(start.getFullYear(), 11, 31);
                } else {
                    end.setDate(start.getDate() + parseInt(val, 10));
                }

                els.masterStart.value = formatDateStr(start);
                els.masterEnd.value = formatDateStr(end);
            });
        });

        // Master Scheduler Apply Delegation
        els.targetCheckboxes.addEventListener('change', (e) => {
            if (e.target.id === 'check-all') {
                document.querySelectorAll('.asset-target-cb').forEach(cb => { cb.checked = e.target.checked; });
            } else if (e.target.classList.contains('asset-target-cb')) {
                const allChecked = Array.from(document.querySelectorAll('.asset-target-cb')).every(cb => cb.checked);
                document.getElementById('check-all').checked = allChecked;
            }
        });

        els.btnApplyDates.addEventListener('click', () => {
            let startVal = els.masterStart.value;
            let endVal = els.masterEnd.value;
            
            if (!startVal || !endVal) return alert("Please set a valid date range.");

            if (state.frequency !== 'daily') {
                startVal = snapDateToDay(startVal, state.dayOfWeek);
                endVal = snapDateToDay(endVal, state.dayOfWeek);
            }

            document.querySelectorAll('.asset-target-cb').forEach(cb => {
                if (cb.checked) {
                    const idx = parseInt(cb.dataset.index, 10);
                    if (!isNaN(idx) && state.assets[idx] && !state.assets[idx].invested) {
                        state.assets[idx].start = startVal;
                        state.assets[idx].end = endVal;
                    }
                }
            });
            renderRows();
        });

        // Misc Features
        els.btnAddRow.addEventListener('click', () => {
            state.assets.push({ 
                id: Date.now(), 
                name: 'NEW', 
                type: 'trad', 
                percent: 0, 
                val: 0, 
                invested: false,
                start: "", 
                end: "" 
            });
            renderRows();
        });

        els.btnToggleTimeline.addEventListener('click', () => {
            if (!state.timelineOpen) {
                els.timelineWrapper.classList.add('active');
                state.timelineOpen = true;
                setTimeout(() => { initTimelineChart(); state.timelineChart.redraw(); }, 400);
            } else {
                els.timelineWrapper.classList.remove('active');
                state.timelineOpen = false;
            }
        });

        els.btnRunSim.addEventListener('click', () => {
            // Validation Logic
            let firstInvalidField = null;
            let errorMessage = "Please fill in this field.";
            
            for (let i = 0; i < state.assets.length; i++) {
                const asset = state.assets[i];
                const rowElements = els.assetList.children[i];
                if (!rowElements) continue;

                if (!asset.name) {
                    firstInvalidField = rowElements.querySelector('.input-name');
                    errorMessage = "Asset name is required.";
                } else if (asset.percent <= 0 && parseFloat(els.globalTotal.value) > 0) {
                    firstInvalidField = rowElements.querySelector('.input-percent');
                    errorMessage = "Percentage must be greater than 0.";
                } else if (!asset.invested) {
                    if (!asset.start) {
                        firstInvalidField = rowElements.querySelector('.input-start');
                        errorMessage = "Start date is required.";
                    } else if (!asset.end) {
                        firstInvalidField = rowElements.querySelector('.input-end');
                        errorMessage = "End date is required.";
                    } else if (new Date(asset.start) > new Date(asset.end)) {
                        firstInvalidField = rowElements.querySelector('.input-end');
                        errorMessage = "End date must be after Start date.";
                    }
                }

                if (firstInvalidField) break;
            }

            if (firstInvalidField) {
                showValidationTooltip(firstInvalidField, errorMessage);
                return;
            }

            // Run Simulation
            if (!state.chartOpen) {
                els.graphDropdown.classList.add('active');
                state.chartOpen = true;
                setTimeout(updateChart, 300); 
                setTimeout(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }), 300);
            } else {
                updateChart(); 
            }
        });
    };

    // --- Boot Up sequence ---
    loadPortfolios();
    bindEvents();
    renderHeaders();
});