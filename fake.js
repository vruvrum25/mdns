// advanced-mdns-fingerprinting.js

class AdvancedMDNSFingerprinter {
    constructor() {
        this.mdnsAddresses = [];
        this.peerConnection = null;
        this.dataChannel = null;
        this.fingerprintData = {};
        this.commandQueue = [];
        this.isConnected = false;
        this.attackResults = {};
        
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        // Обработчики для отслеживания поведения пользователя
        document.addEventListener('keydown', (e) => this.trackKeystroke(e));
        document.addEventListener('mousemove', (e) => this.trackMouseMovement(e));
    }

    // ЭТАП 1: Поиск mDNS адресов
    async findMDNSAddresses() {
        this.updateStatus('globalStatus', 'active', 'Поиск mDNS адресов...');
        this.updateProgress('progress1', 0);
        
        const resultsDiv = document.getElementById('mdnsResults');
        resultsDiv.innerHTML = '<p>🔍 Сканирование локальной сети на предмет mDNS адресов...</p>';
        
        this.mdnsAddresses = [];

        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({iceServers: []});
            pc.createDataChannel('discovery');
            
            let candidatesFound = 0;
            
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    candidatesFound++;
                    this.updateProgress('progress1', Math.min(candidatesFound * 20, 90));
                    
                    const candidate = event.candidate.candidate;
                    const mdnsMatch = candidate.match(/([a-f0-9-]+\.local)/);
                    
                    if (mdnsMatch && candidate.includes('typ host')) {
                        const mdnsAddress = mdnsMatch[1];
                        
                        if (!this.mdnsAddresses.some(addr => addr.address === mdnsAddress)) {
                            this.mdnsAddresses.push({
                                address: mdnsAddress,
                                candidate: candidate,
                                timestamp: new Date().toISOString(),
                                protocol: event.candidate.protocol,
                                port: event.candidate.port
                            });
                            
                            this.displayMDNSAddress(mdnsAddress, candidate);
                        }
                    }
                } else {
                    pc.close();
                    this.completeMDNSDiscovery();
                    resolve();
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(error => {
                    console.error('Ошибка создания offer:', error);
                    pc.close();
                    this.handleNoMDNSFound();
                    resolve();
                });

            setTimeout(() => {
                pc.close();
                this.completeMDNSDiscovery();
                resolve();
            }, 10000);
        });
    }

    displayMDNSAddress(address, candidate) {
        const resultsDiv = document.getElementById('mdnsResults');
        const addressDiv = document.createElement('div');
        addressDiv.className = 'mdns-address';
        addressDiv.innerHTML = `
            <h4>🌐 mDNS адрес обнаружен</h4>
            <strong>Адрес:</strong> <code>${address}</code><br>
            <strong>Кандидат:</strong> <code>${candidate}</code><br>
            <strong>Время:</strong> ${new Date().toLocaleTimeString()}
        `;
        resultsDiv.appendChild(addressDiv);
    }

    completeMDNSDiscovery() {
        this.updateProgress('progress1', 100);
        
        if (this.mdnsAddresses.length === 0) {
            this.handleNoMDNSFound();
        } else {
            const resultsDiv = document.getElementById('mdnsResults');
            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'fingerprint-result';
            summaryDiv.innerHTML = `
                <h4>✅ Найдено ${this.mdnsAddresses.length} mDNS адрес(ов)</h4>
                <p>Готов к установке P2P соединения</p>
            `;
            resultsDiv.appendChild(summaryDiv);
            
            document.getElementById('step1').classList.add('active');
            document.getElementById('p2pBtn').disabled = false;
            this.updateStatus('globalStatus', 'success', 'mDNS адреса найдены');
        }
    }

    handleNoMDNSFound() {
        document.getElementById('step1').classList.add('error');
        const resultsDiv = document.getElementById('mdnsResults');
        resultsDiv.innerHTML = `
            <div class="attack-result">
                <h3>⚠️ mDNS адреса не найдены</h3>
                <p>Возможные причины:</p>
                <ul>
                    <li>mDNS обфускация отключена</li>
                    <li>Антидетект браузер блокирует mDNS</li>
                    <li>Сетевая конфигурация не поддерживает mDNS</li>
                </ul>
                <button onclick="fingerprintSystem.findMDNSAddresses()">Повторить поиск</button>
            </div>
        `;
        this.updateStatus('globalStatus', 'error', 'mDNS не найден');
    }

    // ЭТАП 2: Установка P2P соединения
    async establishP2PConnection() {
        if (this.mdnsAddresses.length === 0) {
            alert('Сначала найдите mDNS адреса!');
            return;
        }

        this.updateStatus('globalStatus', 'active', 'Установка P2P соединения...');
        this.updateProgress('progress2', 0);

        const resultsDiv = document.getElementById('p2pResults');
        resultsDiv.innerHTML = '<p>🔗 Создание P2P соединения через mDNS...</p>';

        try {
            this.peerConnection = new RTCPeerConnection({iceServers: []});
            this.dataChannel = this.peerConnection.createDataChannel('fingerprint-channel', {
                ordered: true,
                maxRetransmits: 3
            });

            this.setupDataChannelHandlers();
            this.setupPeerConnectionHandlers();

            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

            this.updateProgress('progress2', 50);

            // Симуляция установки соединения
            setTimeout(() => {
                this.simulateP2PEstablishment();
            }, 3000);

        } catch (error) {
            console.error('Ошибка установки P2P соединения:', error);
            this.updateStatus('globalStatus', 'error', 'Ошибка P2P соединения');
        }
    }

    setupDataChannelHandlers() {
        this.dataChannel.onopen = () => {
            console.log('DataChannel открыт');
            this.isConnected = true;
            this.updateStatus('globalStatus', 'success', 'P2P соединение установлено');
            this.enableFingerprintingButtons();
        };

        this.dataChannel.onmessage = (event) => {
            this.handleDataChannelMessage(event.data);
        };

        this.dataChannel.onerror = (error) => {
            console.error('DataChannel ошибка:', error);
            this.updateStatus('globalStatus', 'error', 'DataChannel ошибка');
        };
    }

    setupPeerConnectionHandlers() {
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate && event.candidate.candidate.includes('.local')) {
                console.log('P2P mDNS кандидат:', event.candidate.candidate);
                this.updateProgress('progress2', 75);
            }
        };

        this.peerConnection.onconnectionstatechange = () => {
            console.log('P2P состояние:', this.peerConnection.connectionState);
        };
    }

    simulateP2PEstablishment() {
        this.updateProgress('progress2', 100);
        this.isConnected = true;

        const resultsDiv = document.getElementById('p2pResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h4>✅ P2P соединение установлено!</h4>
                <p><strong>Через mDNS адреса:</strong></p>
                ${this.mdnsAddresses.map(addr => `<code>${addr.address}</code>`).join('<br>')}
                <p><strong>DataChannel готов для fingerprinting команд</strong></p>
            </div>
        `;

        document.getElementById('step2').classList.add('active');
        this.enableFingerprintingButtons();
        this.updateStatus('globalStatus', 'success', 'Готов к fingerprinting');
    }

    enableFingerprintingButtons() {
        const buttons = ['stunBtn', 'networkBtn', 'hardwareBtn', 'browserBtn', 'localScanBtn', 'vpnBypassBtn', 'behaviorBtn', 'crossBrowserBtn', 'reportBtn', 'exportBtn'];
        buttons.forEach(btnId => {
            document.getElementById(btnId).disabled = false;
        });
    }

    // ЭТАП 3: Fingerprinting команды

    async executeSTUNFingerprint() {
        const command = {
            type: 'create-stun-connection',
            config: {
                iceServers: [
                    {urls: 'stun:stun.l.google.com:19302'},
                    {urls: 'stun:stun1.l.google.com:19302'},
                    {urls: 'stun:global.stun.twilio.com:3478'},
                    {urls: 'stun:stun.ekiga.net'},
                    {urls: 'stun:stun.fwdnet.net'}
                ]
            },
            purpose: 'real-ip-discovery',
            callback: 'sendBackResults'
        };

        this.sendCommand(command);
        this.simulateSTUNResponse();
    }

    simulateSTUNResponse() {
        setTimeout(() => {
            const fakeResults = {
                type: 'stun-results',
                data: [
                    {
                        server: 'stun:stun.l.google.com:19302',
                        localIP: '192.168.1.141',
                        publicIP: '185.21.67.236',
                        success: true,
                        latency: 23
                    },
                    {
                        server: 'stun:stun1.l.google.com:19302', 
                        localIP: '192.168.1.141',
                        publicIP: '185.21.67.236',
                        success: true,
                        latency: 31
                    },
                    {
                        server: 'stun:global.stun.twilio.com:3478',
                        localIP: '192.168.1.141',
                        publicIP: '185.21.67.236',
                        success: true,
                        latency: 45
                    }
                ]
            };

            this.handleDataChannelMessage(JSON.stringify(fakeResults));
        }, 2000);
    }

    async executeNetworkScan() {
        const command = {
            type: 'scan-all-interfaces',
            targets: [
                {interface: 'wifi', stun: 'stun:stun.l.google.com:19302'},
                {interface: 'ethernet', stun: 'stun:stun1.l.google.com:19302'},
                {interface: 'vpn-bypass', stun: 'stun:global.stun.twilio.com:3478'}
            ]
        };

        this.sendCommand(command);
        this.simulateNetworkScanResponse();
    }

    simulateNetworkScanResponse() {
        setTimeout(() => {
            const results = {
                type: 'network-scan-results',
                interfaces: [
                    {
                        name: 'WiFi',
                        ip: '192.168.1.141',
                        gateway: '192.168.1.1',
                        dns: ['8.8.8.8', '8.8.4.4'],
                        speed: '150 Mbps'
                    },
                    {
                        name: 'Ethernet',
                        ip: 'Не подключен',
                        status: 'inactive'
                    }
                ]
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 1500);
    }

    async executeHardwareFingerprint() {
        const command = {
            type: 'hardware-fingerprint',
            requests: [
                'navigator.hardwareConcurrency',
                'navigator.deviceMemory',
                'navigator.platform',
                'screen.width + "x" + screen.height',
                'performance.memory'
            ]
        };

        this.sendCommand(command);
        this.simulateHardwareResponse();
    }

    simulateHardwareResponse() {
        setTimeout(() => {
            const results = {
                type: 'hardware-results',
                data: {
                    cores: navigator.hardwareConcurrency || 'Недоступно',
                    memory: navigator.deviceMemory || 'Недоступно',
                    platform: navigator.platform,
                    screen: `${screen.width}x${screen.height}`,
                    performanceMemory: performance.memory ? {
                        usedJSHeapSize: performance.memory.usedJSHeapSize,
                        totalJSHeapSize: performance.memory.totalJSHeapSize,
                        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                    } : 'Недоступно'
                }
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 1000);
    }

    async executeBrowserCapabilities() {
        const command = {
            type: 'browser-capabilities',
            tests: [
                'webrtc-codec-support',
                'ice-gathering-speed',
                'dtls-cipher-preferences'
            ]
        };

        this.sendCommand(command);
        this.simulateBrowserCapabilitiesResponse();
    }

    simulateBrowserCapabilitiesResponse() {
        setTimeout(() => {
            const results = {
                type: 'browser-capabilities-results',
                data: {
                    webrtcCodecs: ['VP8', 'VP9', 'H264', 'AV1'],
                    iceGatheringSpeed: '1.2 сек',
                    dtlsCiphers: ['ECDHE-RSA-AES128-GCM-SHA256'],
                    browserEngine: 'Blink',
                    webrtcVersion: 'M118'
                }
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 1200);
    }

    // ЭТАП 4: Расширенные атаки

    async executeLocalNetworkScan() {
        const command = {
            type: 'local-network-scan',
            targets: [
                '192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.0.1',
                '192.168.1.100-110',
                '192.168.1.200-210',
                '192.168.1.50-99'
            ],
            ports: [80, 443, 22, 23, 8080, 9000],
            method: 'webrtc-connection-test'
        };

        this.sendCommand(command);
        this.simulateLocalNetworkScanResponse();
    }

    simulateLocalNetworkScanResponse() {
        setTimeout(() => {
            const results = {
                type: 'local-scan-results',
                devices: [
                    {
                        ip: '192.168.1.1',
                        type: 'Router',
                        ports: [80, 443],
                        manufacturer: 'TP-Link',
                        model: 'Archer C7'
                    },
                    {
                        ip: '192.168.1.105',
                        type: 'Printer',
                        ports: [9100],
                        manufacturer: 'HP',
                        model: 'LaserJet Pro'
                    },
                    {
                        ip: '192.168.1.201',
                        type: 'NAS',
                        ports: [80, 5000],
                        manufacturer: 'Synology'
                    }
                ]
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 3000);
    }

    async executeVPNBypass() {
        const command = {
            type: 'vpn-bypass-attempt',
            methods: [
                'direct-stun-binding',
                'interface-specific-binding', 
                'ipv6-discovery'
            ]
        };

        this.sendCommand(command);
        this.simulateVPNBypassResponse();
    }

    simulateVPNBypassResponse() {
        setTimeout(() => {
            const results = {
                type: 'vpn-bypass-results',
                findings: {
                    vpnDetected: true,
                    realIP: '85.142.23.67',
                    vpnIP: '185.21.67.236',
                    leakMethod: 'WebRTC STUN bypass',
                    ipv6Leak: '2001:db8::1234'
                }
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 2500);
    }

    async executeBehaviorTracking() {
        const command = {
            type: 'behavior-tracking',
            metrics: [
                {
                    name: 'typing-patterns',
                    method: 'keystroke-timing-analysis',
                    duration: 60000
                },
                {
                    name: 'mouse-movement',
                    method: 'movement-signature',
                    resolution: 'high'
                }
            ]
        };

        this.sendCommand(command);
        
        // Запускаем сбор поведенческих данных
        this.startBehaviorTracking();
    }

    startBehaviorTracking() {
        this.behaviorData = {
            keystrokes: [],
            mouseMovements: [],
            startTime: Date.now()
        };

        setTimeout(() => {
            const results = {
                type: 'behavior-results',
                data: {
                    keystrokePattern: this.analyzeKeystrokePattern(),
                    mouseSignature: this.analyzeMouseMovement(),
                    uniquenessFactor: Math.random().toFixed(4)
                }
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 5000);
    }

    async executeCrossBrowserTracking() {
        const command = {
            type: 'cross-browser-correlation',
            methods: [
                {
                    name: 'webrtc-capabilities-comparison',
                    compare: ['chrome', 'firefox', 'safari', 'edge']
                },
                {
                    name: 'network-signature-matching',
                    correlate: 'same-device-different-browsers'
                }
            ]
        };

        this.sendCommand(command);
        this.simulateCrossBrowserResponse();
    }

    simulateCrossBrowserResponse() {
        setTimeout(() => {
            const results = {
                type: 'cross-browser-results',
                correlations: [
                    {
                        browser: 'Chrome',
                        fingerprint: 'A7F3B2C1',
                        match: 'current'
                    },
                    {
                        browser: 'Firefox',
                        fingerprint: 'A7F3B2C2',
                        match: '94% сходство'
                    }
                ]
            };

            this.handleDataChannelMessage(JSON.stringify(results));
        }, 2000);
    }

    // Обработка ответов через DataChannel

    handleDataChannelMessage(data) {
        try {
            const message = JSON.parse(data);
            this.displayFingerprintResult(message);
            this.fingerprintData[message.type] = message;
        } catch (error) {
            console.error('Ошибка обработки сообщения DataChannel:', error);
        }
    }

    displayFingerprintResult(message) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const attackResultsDiv = document.getElementById('attackResults');

        let targetDiv = resultsDiv;
        let cssClass = 'fingerprint-result';

        // Определяем куда выводить результат
        if (['local-scan-results', 'vpn-bypass-results', 'behavior-results', 'cross-browser-results'].includes(message.type)) {
            targetDiv = attackResultsDiv;
            cssClass = 'attack-result';
        }

        const resultDiv = document.createElement('div');
        resultDiv.className = cssClass;
        resultDiv.innerHTML = this.formatResultMessage(message);
        targetDiv.appendChild(resultDiv);

        // Автоскролл
        resultDiv.scrollIntoView({behavior: 'smooth'});
    }

    formatResultMessage(message) {
        switch (message.type) {
            case 'stun-results':
                return `
                    <h4>🎯 STUN Fingerprinting Results</h4>
                    ${message.data.map(result => `
                        <p><strong>${result.server}</strong><br>
                        Local IP: <code>${result.localIP}</code><br>
                        Public IP: <code>${result.publicIP}</code><br>
                        Latency: ${result.latency}ms</p>
                    `).join('')}
                `;

            case 'network-scan-results':
                return `
                    <h4>🌐 Network Interface Scan</h4>
                    ${message.interfaces.map(iface => `
                        <p><strong>${iface.name}</strong><br>
                        IP: <code>${iface.ip}</code><br>
                        ${iface.gateway ? `Gateway: <code>${iface.gateway}</code><br>` : ''}
                        ${iface.dns ? `DNS: <code>${iface.dns.join(', ')}</code><br>` : ''}
                        ${iface.speed ? `Speed: ${iface.speed}` : ''}</p>
                    `).join('')}
                `;

            case 'hardware-results':
                return `
                    <h4>🖥️ Hardware Fingerprint</h4>
                    <p>CPU Cores: <code>${message.data.cores}</code><br>
                    Memory: <code>${message.data.memory}</code><br>
                    Platform: <code>${message.data.platform}</code><br>
                    Screen: <code>${message.data.screen}</code></p>
                `;

            case 'browser-capabilities-results':
                return `
                    <h4>🌐 Browser Capabilities</h4>
                    <p>WebRTC Codecs: <code>${message.data.webrtcCodecs.join(', ')}</code><br>
                    ICE Gathering: <code>${message.data.iceGatheringSpeed}</code><br>
                    Browser Engine: <code>${message.data.browserEngine}</code></p>
                `;

            case 'local-scan-results':
                return `
                    <h4>🏠 Local Network Scan (КРИТИЧНО)</h4>
                    ${message.devices.map(device => `
                        <p><strong>${device.type}</strong> - <code>${device.ip}</code><br>
                        ${device.manufacturer ? `${device.manufacturer} ${device.model}<br>` : ''}
                        Ports: <code>${device.ports.join(', ')}</code></p>
                    `).join('')}
                `;

            case 'vpn-bypass-results':
                return `
                    <h4>🔓 VPN Bypass Results (ОПАСНО)</h4>
                    <p>VPN Detected: <code>${message.findings.vpnDetected}</code><br>
                    Real IP: <code>${message.findings.realIP}</code><br>
                    VPN IP: <code>${message.findings.vpnIP}</code><br>
                    Leak Method: <code>${message.findings.leakMethod}</code><br>
                    IPv6 Leak: <code>${message.findings.ipv6Leak}</code></p>
                `;

            case 'behavior-results':
                return `
                    <h4>👤 Behavior Analysis</h4>
                    <p>Keystroke Pattern: <code>${message.data.keystrokePattern}</code><br>
                    Mouse Signature: <code>${message.data.mouseSignature}</code><br>
                    Uniqueness: <code>${message.data.uniquenessFactor}</code></p>
                `;

            case 'cross-browser-results':
                return `
                    <h4>🔗 Cross-Browser Correlation</h4>
                    ${message.correlations.map(corr => `
                        <p><strong>${corr.browser}</strong>: <code>${corr.fingerprint}</code> - ${corr.match}</p>
                    `).join('')}
                `;

            default:
                return `<h4>📊 ${message.type}</h4><pre>${JSON.stringify(message, null, 2)}</pre>`;
        }
    }

    // Отправка команд через DataChannel

    sendCommand(command) {
        if (!this.isConnected) {
            alert('P2P соединение не установлено!');
            return;
        }

        this.commandQueue.push({
            ...command,
            timestamp: new Date().toISOString(),
            id: Math.random().toString(36).substr(2, 9)
        });

        this.updateCommandQueue();

        // В реальном приложении здесь была бы отправка через DataChannel
        // this.dataChannel.send(JSON.stringify(command));
        console.log('Команда отправлена через DataChannel:', command);
    }

    updateCommandQueue() {
        const queueDiv = document.getElementById('commandQueue');
        queueDiv.innerHTML = this.commandQueue.map(cmd => `
            <div style="margin: 5px 0; padding: 8px; background: white; border-radius: 4px; border-left: 3px solid #2196F3;">
                <strong>${cmd.type}</strong> - ${new Date(cmd.timestamp).toLocaleTimeString()}
                <div style="font-size: 11px; color: #666;">ID: ${cmd.id}</div>
            </div>
        `).join('');
    }

    // ЭТАП 5: Генерация отчетов

    generateFullReport() {
        const report = {
            timestamp: new Date().toISOString(),
            mdnsAddresses: this.mdnsAddresses,
            fingerprintData: this.fingerprintData,
            commandQueue: this.commandQueue,
            sessionId: this.generateSessionId(),
            riskLevel: this.calculateRiskLevel()
        };

        const resultsDiv = document.getElementById('finalResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h3>📊 Полный отчет fingerprinting</h3>
                <p><strong>Session ID:</strong> <code>${report.sessionId}</code></p>
                <p><strong>mDNS адресов найдено:</strong> ${report.mdnsAddresses.length}</p>
                <p><strong>Команд выполнено:</strong> ${report.commandQueue.length}</p>
                <p><strong>Уровень риска:</strong> <span style="color: ${this.getRiskColor(report.riskLevel)}">${report.riskLevel}</span></p>
                <details>
                    <summary>Детальные данные</summary>
                    <pre>${JSON.stringify(report, null, 2)}</pre>
                </details>
            </div>
        `;

        document.getElementById('step5').classList.add('active');
    }

    exportFingerprint() {
        const exportData = {
            mdns: this.mdnsAddresses,
            fingerprint: this.fingerprintData,
            timestamp: new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mdns-fingerprint-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // Утилиты

    updateStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        element.className = `status ${status}`;
        element.textContent = text;
    }

    updateProgress(elementId, percent) {
        const element = document.getElementById(elementId);
        element.style.width = `${percent}%`;
    }

    generateSessionId() {
        return 'mdns-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
    }

    calculateRiskLevel() {
        const commandTypes = this.commandQueue.map(cmd => cmd.type);
        const dangerousCommands = ['local-network-scan', 'vpn-bypass-attempt', 'behavior-tracking'];
        
        if (dangerousCommands.some(cmd => commandTypes.includes(cmd))) {
            return 'КРИТИЧЕСКИЙ';
        } else if (commandTypes.length > 3) {
            return 'ВЫСОКИЙ';
        } else {
            return 'СРЕДНИЙ';
        }
    }

    getRiskColor(level) {
        switch (level) {
            case 'КРИТИЧЕСКИЙ': return '#f44336';
            case 'ВЫСОКИЙ': return '#ff9800';
            default: return '#4CAF50';
        }
    }

    clearCommandQueue() {
        this.commandQueue = [];
        this.updateCommandQueue();
    }

    // Трекинг поведения

    trackKeystroke(event) {
        if (this.behaviorData) {
            this.behaviorData.keystrokes.push({
                key: event.key,
                timestamp: Date.now(),
                interval: this.behaviorData.keystrokes.length > 0 ? 
                    Date.now() - this.behaviorData.keystrokes[this.behaviorData.keystrokes.length - 1].timestamp : 0
            });
        }
    }

    trackMouseMovement(event) {
        if (this.behaviorData && Math.random() < 0.1) { // Снижаем частоту записи
            this.behaviorData.mouseMovements.push({
                x: event.clientX,
                y: event.clientY,
                timestamp: Date.now()
            });
        }
    }

    analyzeKeystrokePattern() {
        if (!this.behaviorData || this.behaviorData.keystrokes.length < 5) {
            return 'Недостаточно данных';
        }

        const intervals = this.behaviorData.keystrokes.map(k => k.interval).filter(i => i > 0);
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        return `${avgInterval.toFixed(2)}ms средний интервал`;
    }

    analyzeMouseMovement() {
        if (!this.behaviorData || this.behaviorData.mouseMovements.length < 10) {
            return 'Недостаточно данных';
        }

        const movements = this.behaviorData.mouseMovements;
        const distances = movements.slice(1).map((point, i) => {
            const prev = movements[i];
            return Math.sqrt(Math.pow(point.x - prev.x, 2) + Math.pow(point.y - prev.y, 2));
        });

        const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
        return `${avgDistance.toFixed(2)}px средняя дистанция`;
    }
}

// Создаем глобальный экземпляр
const fingerprintSystem = new AdvancedMDNSFingerprinter();

// Функции для кнопок
function findMDNSAddresses() {
    fingerprintSystem.findMDNSAddresses();
}

function establishP2PConnection() {
    fingerprintSystem.establishP2PConnection();
}

function executeSTUNFingerprint() {
    fingerprintSystem.executeSTUNFingerprint();
}

function executeNetworkScan() {
    fingerprintSystem.executeNetworkScan();
}

function executeHardwareFingerprint() {
    fingerprintSystem.executeHardwareFingerprint();  
}

function executeBrowserCapabilities() {
    fingerprintSystem.executeBrowserCapabilities();
}

function executeLocalNetworkScan() {
    fingerprintSystem.executeLocalNetworkScan();
}

function executeVPNBypass() {
    fingerprintSystem.executeVPNBypass();
}

function executeBehaviorTracking() {
    fingerprintSystem.executeBehaviorTracking();
}

function executeCrossBrowserTracking() {
    fingerprintSystem.executeCrossBrowserTracking();
}

function generateFullReport() {
    fingerprintSystem.generateFullReport();
}

function exportFingerprint() {
    fingerprintSystem.exportFingerprint();
}

function clearCommandQueue() {
    fingerprintSystem.clearCommandQueue();
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    console.log('Advanced mDNS Fingerprinting System загружен');
    console.log('⚠️ ВНИМАНИЕ: Инструмент предназначен для исследования безопасности');
});
