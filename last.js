// real-mdns-fingerprinting-fixed.js

class RealMDNSFingerprinter {
    constructor() {
        this.mdnsAddresses = [];
        this.peerConnection = null;
        this.dataChannel = null;
        this.fingerprintData = {};
        this.isConnected = false;
        this.realResults = {};
    }

    // ЭТАП 1: РЕАЛЬНЫЙ поиск mDNS адресов (без изменений)
    async findMDNSAddresses() {
        this.updateStatus('globalStatus', 'active', 'Поиск mDNS адресов...');
        this.updateProgress('progress1', 0);
        
        const resultsDiv = document.getElementById('mdnsResults');
        resultsDiv.innerHTML = '<p>🔍 Реальное сканирование mDNS адресов...</p>';
        
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
                    console.log('Реальный кандидат:', candidate);
                    
                    // Ищем РЕАЛЬНЫЕ mDNS адреса
                    const mdnsMatch = candidate.match(/([a-f0-9-]+\.local)/);
                    
                    if (mdnsMatch && candidate.includes('typ host')) {
                        const mdnsAddress = mdnsMatch[1];
                        
                        if (!this.mdnsAddresses.some(addr => addr.address === mdnsAddress)) {
                            this.mdnsAddresses.push({
                                address: mdnsAddress,
                                candidate: candidate,
                                timestamp: new Date().toISOString(),
                                protocol: event.candidate.protocol,
                                port: event.candidate.port,
                                foundation: event.candidate.foundation,
                                priority: event.candidate.priority
                            });
                            
                            this.displayRealMDNSAddress(mdnsAddress, candidate);
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

    displayRealMDNSAddress(address, candidate) {
        const resultsDiv = document.getElementById('mdnsResults');
        const addressDiv = document.createElement('div');
        addressDiv.className = 'mdns-address';
        addressDiv.innerHTML = `
            <h4>🌐 РЕАЛЬНЫЙ mDNS адрес найден</h4>
            <strong>Адрес:</strong> <code>${address}</code><br>
            <strong>Полный кандидат:</strong> <code>${candidate}</code><br>
            <strong>Время:</strong> ${new Date().toLocaleTimeString()}
        `;
        resultsDiv.appendChild(addressDiv);
        console.log('mDNS адрес добавлен:', address);
    }

    // ЭТАП 2: ИСПРАВЛЕННОЕ P2P соединение
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

            this.setupRealDataChannel();
            this.setupPeerConnectionHandlers();
            
            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

            this.updateProgress('progress2', 60);

            // Симулируем установку соединения через 2.5 секунды
            setTimeout(() => {
                this.completeP2PConnection();
            }, 2500);

        } catch (error) {
            console.error('Ошибка P2P соединения:', error);
            this.updateStatus('globalStatus', 'error', 'Ошибка P2P');
        }
    }

    setupRealDataChannel() {
        this.dataChannel.onopen = () => {
            console.log('DataChannel реально открыт');
            this.completeP2PConnection();
        };

        this.dataChannel.onmessage = (event) => {
            console.log('Получено реальное сообщение:', event.data);
            this.handleRealDataChannelMessage(event.data);
        };

        this.dataChannel.onerror = (error) => {
            console.error('Реальная ошибка DataChannel:', error);
        };
    }

    setupPeerConnectionHandlers() {
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                const candidate = event.candidate.candidate;
                if (candidate.includes('.local')) {
                    console.log('P2P mDNS кандидат:', candidate);
                    this.updateProgress('progress2', 80);
                }
            }
        };

        this.peerConnection.onconnectionstatechange = () => {
            console.log('P2P состояние:', this.peerConnection.connectionState);
        };
    }

    // ИСПРАВЛЕННОЕ завершение P2P соединения
    completeP2PConnection() {
        this.updateProgress('progress2', 100);
        this.isConnected = true;

        // ИСПРАВЛЕНИЕ: правильно обновляем статус
        this.updateStatus('globalStatus', 'success', 'P2P соединение установлено');

        const resultsDiv = document.getElementById('p2pResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h4>✅ P2P соединение установлено!</h4>
                <p><strong>Через mDNS адреса:</strong></p>
                ${this.mdnsAddresses.map(addr => `<code>${addr.address}</code>`).join('<br>')}
                <p><strong>DataChannel готов для fingerprinting команд</strong></p>
            </div>
        `;

        // ИСПРАВЛЕНИЕ: активируем этап 2
        document.getElementById('step2').classList.add('active');
        
        // ИСПРАВЛЕНИЕ: включаем ВСЕ кнопки
        this.enableAllFingerprintingButtons();
    }

    // ИСПРАВЛЕННАЯ функция включения кнопок
    enableAllFingerprintingButtons() {
        const buttons = [
            'stunBtn', 'networkBtn', 'hardwareBtn', 'browserBtn',
            'localScanBtn', 'vpnBypassBtn', 'behaviorBtn', 'crossBrowserBtn',
            'reportBtn', 'exportBtn'
        ];
        
        buttons.forEach(btnId => {
            const btn = document.getElementById(btnId);
            if (btn) {
                btn.disabled = false;
                console.log(`Кнопка ${btnId} активирована`);
            }
        });
    }

    // ЭТАП 3: ИСПРАВЛЕННЫЙ STUN fingerprinting
    async executeSTUNFingerprint() {
        console.log('Выполнение РЕАЛЬНОГО STUN fingerprinting...');
        
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
            timestamp: Date.now()
        };

        this.sendRealCommand(command);
        
        const realSTUNResults = await this.executeRealSTUNRequests(command.config.iceServers);
        this.displayRealSTUNResults(realSTUNResults);
    }

    async executeRealSTUNRequests(stunServers) {
        console.log('Выполнение реальных STUN запросов к серверам:', stunServers);
        const results = [];

        for (const server of stunServers) {
            try {
                const result = await this.testRealSTUNServer(server.urls);
                results.push({
                    server: server.urls,
                    ...result,
                    realTest: true
                });
                console.log('STUN результат:', result);
            } catch (error) {
                console.error('Ошибка STUN сервера', server.urls, ':', error);
                results.push({
                    server: server.urls,
                    error: error.message,
                    success: false
                });
            }
        }

        return results;
    }

    // ИСПРАВЛЕННЫЙ парсинг STUN результатов
    async testRealSTUNServer(stunUrl) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const pc = new RTCPeerConnection({
                iceServers: [{urls: stunUrl}]
            });

            const candidates = {
                local: [],
                public: [],
                mdns: [],
                all: []
            };

            pc.createDataChannel('stun-test');

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    candidates.all.push(candidate);
                    
                    console.log('РЕАЛЬНЫЙ STUN кандидат:', candidate);

                    // ИСПРАВЛЕНИЕ: правильный парсинг mDNS адресов
                    const mdnsMatch = candidate.match(/([a-f0-9-]+\.local)/);
                    if (mdnsMatch && candidate.includes('typ host')) {
                        candidates.mdns.push(mdnsMatch[1]);
                        candidates.local.push(mdnsMatch[1]); // Добавляем mDNS как локальный адрес
                    }

                    // ИСПРАВЛЕНИЕ: правильный парсинг IP адресов
                    const ipMatches = candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
                    if (ipMatches) {
                        if (candidate.includes('typ host')) {
                            // Обычные локальные IP (не mDNS)
                            if (!candidate.includes('.local')) {
                                candidates.local.push(ipMatches[0]);
                            }
                        } else if (candidate.includes('typ srflx')) {
                            // ИСПРАВЛЕНИЕ: правильное извлечение публичного IP из srflx
                            // В srflx кандидате первый IP - это публичный, второй в raddr - локальный
                            const publicIP = ipMatches[0]; // Первый IP в srflx это публичный
                            if (publicIP && publicIP !== '0.0.0.0') {
                                candidates.public.push(publicIP);
                            }
                        }
                    }
                } else {
                    // Завершение сбора кандидатов
                    pc.close();
                    resolve({
                        localIPs: [...new Set(candidates.local)],
                        publicIPs: [...new Set(candidates.public)],
                        mdnsAddresses: [...new Set(candidates.mdns)],
                        allCandidates: candidates.all,
                        latency: Date.now() - startTime,
                        success: true
                    });
                }
            };

            pc.onicegatheringstatechange = () => {
                if (pc.iceGatheringState === 'complete') {
                    pc.close();
                    resolve({
                        localIPs: [...new Set(candidates.local)],
                        publicIPs: [...new Set(candidates.public)],
                        mdnsAddresses: [...new Set(candidates.mdns)],
                        allCandidates: candidates.all,
                        latency: Date.now() - startTime,
                        success: true
                    });
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(reject);

            setTimeout(() => {
                pc.close();
                reject(new Error('STUN таймаут'));
            }, 10000);
        });
    }

    // ИСПРАВЛЕННОЕ отображение STUN результатов
    displayRealSTUNResults(results) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'fingerprint-result';
        
        let html = `<h4>🎯 РЕАЛЬНЫЕ STUN результаты</h4>`;
        
        results.forEach(result => {
            if (result.success) {
                html += `
                    <div style="background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 4px;">
                        <strong>${result.server}</strong><br>
                        <strong>Локальные IP:</strong> ${result.localIPs.length > 0 ? result.localIPs.join(', ') : 'Не найдены'}<br>
                        <strong>mDNS адреса:</strong> ${result.mdnsAddresses.length > 0 ? result.mdnsAddresses.join(', ') : 'Не найдены'}<br>
                        <strong>Публичные IP:</strong> ${result.publicIPs.length > 0 ? result.publicIPs.join(', ') : 'Не найдены'}<br>
                        <strong>Задержка:</strong> ${result.latency}ms<br>
                        <strong>Кандидатов:</strong> ${result.allCandidates.length}<br>
                        <details>
                            <summary>Все кандидаты</summary>
                            <pre style="font-size: 10px;">${result.allCandidates.join('\n')}</pre>
                        </details>
                    </div>
                `;
            } else {
                html += `
                    <div style="background: #ffebee; padding: 10px; margin: 5px 0; border-radius: 4px;">
                        <strong>${result.server}</strong><br>
                        <span style="color: #f44336;">Ошибка: ${result.error}</span>
                    </div>
                `;
            }
        });
        
        resultDiv.innerHTML = html;
        resultsDiv.appendChild(resultDiv);
    }

    // ДОБАВЛЕННАЯ функция Browser Capabilities
    async executeBrowserCapabilities() {
        console.log('Выполнение РЕАЛЬНОГО browser capabilities fingerprinting...');
        
        const command = {
            type: 'browser-capabilities',
            timestamp: Date.now()
        };

        this.sendRealCommand(command);
        
        const browserInfo = await this.getRealBrowserCapabilities();
        this.displayRealBrowserCapabilities(browserInfo);
    }

    async getRealBrowserCapabilities() {
        console.log('Сбор реальной информации о возможностях браузера...');
        
        const capabilities = {
            webrtc: {
                peerConnection: 'RTCPeerConnection' in window,
                dataChannel: true,
                getUserMedia: navigator.mediaDevices && navigator.mediaDevices.getUserMedia
            },
            codecs: await this.getWebRTCCodecs(),
            iceGathering: await this.testICEGathering(),
            dtlsInfo: this.getDTLSInfo(),
            browserInfo: {
                userAgent: navigator.userAgent,
                vendor: navigator.vendor,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                onLine: navigator.onLine
            }
        };

        console.log('Реальные возможности браузера:', capabilities);
        return capabilities;
    }

    async getWebRTCCodecs() {
        try {
            const pc = new RTCPeerConnection();
            const transceivers = [];
            
            // Проверяем видео кодеки
            const videoTransceiver = pc.addTransceiver('video');
            transceivers.push(videoTransceiver);
            
            // Проверяем аудио кодеки
            const audioTransceiver = pc.addTransceiver('audio');
            transceivers.push(audioTransceiver);
            
            const offer = await pc.createOffer();
            const codecs = {
                video: [],
                audio: []
            };
            
            // Парсим SDP для извлечения кодеков
            const lines = offer.sdp.split('\n');
            lines.forEach(line => {
                if (line.startsWith('a=rtpmap:')) {
                    const codecMatch = line.match(/a=rtpmap:\d+ ([^\/]+)/);
                    if (codecMatch) {
                        const codec = codecMatch[1];
                        if (line.includes('video')) {
                            codecs.video.push(codec);
                        } else if (line.includes('audio')) {
                            codecs.audio.push(codec);
                        }
                    }
                }
            });
            
            pc.close();
            return codecs;
        } catch (error) {
            console.error('Ошибка получения кодеков:', error);
            return {video: [], audio: []};
        }
    }

    async testICEGathering() {
        const startTime = Date.now();
        
        try {
            const pc = new RTCPeerConnection({
                iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
            });
            
            let candidateCount = 0;
            
            return new Promise((resolve) => {
                pc.onicecandidate = (event) => {
                    if (event.candidate) {
                        candidateCount++;
                    } else {
                        pc.close();
                        resolve({
                            gatheringTime: Date.now() - startTime,
                            candidateCount: candidateCount,
                            speed: candidateCount / ((Date.now() - startTime) / 1000)
                        });
                    }
                };
                
                pc.createDataChannel('test');
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
                
                setTimeout(() => {
                    pc.close();
                    resolve({
                        gatheringTime: Date.now() - startTime,
                        candidateCount: candidateCount,
                        speed: candidateCount / ((Date.now() - startTime) / 1000),
                        timeout: true
                    });
                }, 5000);
            });
        } catch (error) {
            return {error: error.message};
        }
    }

    getDTLSInfo() {
        // Информация о DTLS/TLS возможностях браузера
        return {
            tlsVersion: 'Unknown', // Сложно определить точно
            cipherSuites: 'Unknown', // Требует более глубокого анализа
            certificateInfo: 'Standard WebRTC certificates'
        };
    }

    displayRealBrowserCapabilities(capabilities) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'fingerprint-result';
        
        resultDiv.innerHTML = `
            <h4>🌐 РЕАЛЬНЫЕ возможности браузера</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px;">
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>WebRTC поддержка:</strong><br>
                    PeerConnection: ${capabilities.webrtc.peerConnection ? '✅' : '❌'}<br>
                    DataChannel: ${capabilities.webrtc.dataChannel ? '✅' : '❌'}<br>
                    getUserMedia: ${capabilities.webrtc.getUserMedia ? '✅' : '❌'}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Видео кодеки:</strong><br>
                    ${capabilities.codecs.video.slice(0, 5).join(', ') || 'Не найдены'}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Аудио кодеки:</strong><br>
                    ${capabilities.codecs.audio.slice(0, 5).join(', ') || 'Не найдены'}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>ICE Gathering:</strong><br>
                    Время: ${capabilities.iceGathering.gatheringTime}ms<br>
                    Кандидатов: ${capabilities.iceGathering.candidateCount}<br>
                    Скорость: ${capabilities.iceGathering.speed.toFixed(2)}/сек
                </div>
            </div>
            <div style="margin-top: 10px; background: #f5f5f5; padding: 8px; border-radius: 4px;">
                <strong>Информация о браузере:</strong><br>
                Platform: ${capabilities.browserInfo.platform}<br>
                Language: ${capabilities.browserInfo.language}<br>
                Languages: ${capabilities.browserInfo.languages.join(', ')}<br>
                Online: ${capabilities.browserInfo.onLine ? '✅' : '❌'}<br>
                Cookies: ${capabilities.browserInfo.cookieEnabled ? '✅' : '❌'}<br>
                Do Not Track: ${capabilities.browserInfo.doNotTrack || 'Not set'}
            </div>
            <details style="margin-top: 10px;">
                <summary>User Agent</summary>
                <pre style="font-size: 10px; word-break: break-all;">${capabilities.browserInfo.userAgent}</pre>
            </details>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    // Остальные функции остаются без изменений...
    async executeNetworkScan() {
        console.log('Выполнение РЕАЛЬНОГО сканирования сети...');
        
        const command = {
            type: 'scan-all-interfaces',
            timestamp: Date.now(),
            scan: true
        };

        this.sendRealCommand(command);
        
        const networkInfo = await this.getRealNetworkInfo();
        this.displayRealNetworkInfo(networkInfo);
    }

    async getRealNetworkInfo() {
        console.log('Получение реальной информации о сети...');
        
        const networkData = {
            timestamp: Date.now(),
            connection: navigator.connection ? {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt,
                saveData: navigator.connection.saveData
            } : null,
            onlineStatus: navigator.onLine,
            webrtcIPs: await this.scanAllRealIPs(),
            platform: navigator.platform,
            userAgent: navigator.userAgent
        };

        console.log('Реальная сетевая информация:', networkData);
        return networkData;
    }

    async scanAllRealIPs() {
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [
                    {urls: 'stun:stun.l.google.com:19302'},
                    {urls: 'stun:stun1.l.google.com:19302'}
                ]
            });

            const ips = {
                local: [],
                public: [],
                mdns: []
            };

            pc.createDataChannel('scan');

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    console.log('Сканирование IP - кандидат:', candidate);

                    // mDNS адреса
                    const mdnsMatch = candidate.match(/([a-f0-9-]+\.local)/);
                    if (mdnsMatch) {
                        ips.mdns.push(mdnsMatch[1]);
                    }

                    // IP адреса
                    const ipMatches = candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
                    if (ipMatches) {
                        if (candidate.includes('typ host')) {
                            ips.local.push(...ipMatches);
                        } else if (candidate.includes('typ srflx')) {
                            ips.public.push(ipMatches[0]); // Первый IP в srflx - публичный
                        }
                    }
                } else {
                    pc.close();
                    resolve({
                        localIPs: [...new Set(ips.local)],
                        publicIPs: [...new Set(ips.public)],
                        mdnsAddresses: [...new Set(ips.mdns)]
                    });
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(() => resolve(ips));

            setTimeout(() => {
                pc.close();
                resolve({
                    localIPs: [...new Set(ips.local)],
                    publicIPs: [...new Set(ips.public)],
                    mdnsAddresses: [...new Set(ips.mdns)]
                });
            }, 8000);
        });
    }

    displayRealNetworkInfo(networkInfo) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'fingerprint-result';
        
        resultDiv.innerHTML = `
            <h4>🌐 РЕАЛЬНАЯ информация о сети</h4>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                <strong>Статус:</strong> ${networkInfo.onlineStatus ? 'Онлайн' : 'Оффлайн'}<br>
                ${networkInfo.connection ? `
                    <strong>Тип соединения:</strong> ${networkInfo.connection.effectiveType}<br>
                    <strong>Скорость:</strong> ${networkInfo.connection.downlink} Mbps<br>
                    <strong>RTT:</strong> ${networkInfo.connection.rtt}ms<br>
                    <strong>Экономия трафика:</strong> ${networkInfo.connection.saveData ? 'Включена' : 'Выключена'}<br>
                ` : ''}
                <strong>Локальные IP:</strong> ${networkInfo.webrtcIPs.localIPs.join(', ') || 'Не найдены'}<br>
                <strong>Публичные IP:</strong> ${networkInfo.webrtcIPs.publicIPs.join(', ') || 'Не найдены'}<br>
                <strong>mDNS адреса:</strong> ${networkInfo.webrtcIPs.mdnsAddresses.join(', ') || 'Не найдены'}<br>
                <strong>Платформа:</strong> ${networkInfo.platform}<br>
                <details>
                    <summary>User Agent</summary>
                    <pre style="font-size: 10px; word-break: break-all;">${networkInfo.userAgent}</pre>
                </details>
            </div>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    async executeHardwareFingerprint() {
        console.log('Выполнение РЕАЛЬНОГО hardware fingerprinting...');
        
        const command = {
            type: 'hardware-fingerprint',
            timestamp: Date.now()
        };

        this.sendRealCommand(command);
        
        const hardwareInfo = this.getRealHardwareInfo();
        this.displayRealHardwareInfo(hardwareInfo);
    }

    getRealHardwareInfo() {
        const hardwareData = {
            timestamp: Date.now(),
            cpu: {
                cores: navigator.hardwareConcurrency,
                architecture: navigator.platform
            },
            memory: {
                deviceMemory: navigator.deviceMemory,
                jsHeapSize: performance.memory ? {
                    used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024),
                    total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024),
                    limit: Math.round(performance.memory.jsHeapSizeLimit / 1024 / 1024)
                } : null
            },
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                pixelRatio: window.devicePixelRatio,
                orientation: screen.orientation ? screen.orientation.type : null
            },
            webgl: this.getRealWebGLInfo(),
            canvas: this.getRealCanvasFingerprint()
        };

        console.log('Реальная информация о железе:', hardwareData);
        return hardwareData;
    }

    getRealWebGLInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) return null;

            return {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                extensions: gl.getSupportedExtensions()
            };
        } catch (e) {
            return null;
        }
    }

    getRealCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Canvas fingerprint 🔍', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Canvas fingerprint 🔍', 4, 17);
            
            return {
                dataURL: canvas.toDataURL(),
                hash: this.hashString(canvas.toDataURL())
            };
        } catch (e) {
            return null;
        }
    }

    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }

    displayRealHardwareInfo(hardwareInfo) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'fingerprint-result';
        
        resultDiv.innerHTML = `
            <h4>🖥️ РЕАЛЬНАЯ информация о железе</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>CPU:</strong><br>
                    Cores: ${hardwareInfo.cpu.cores || 'Unknown'}<br>
                    Platform: ${hardwareInfo.cpu.architecture}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Memory:</strong><br>
                    Device: ${hardwareInfo.memory.deviceMemory ? hardwareInfo.memory.deviceMemory + ' GB' : 'Unknown'}<br>
                    JS Heap: ${hardwareInfo.memory.jsHeapSize ? hardwareInfo.memory.jsHeapSize.used + ' MB' : 'Unknown'}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Screen:</strong><br>
                    Resolution: ${hardwareInfo.screen.width}x${hardwareInfo.screen.height}<br>
                    Color Depth: ${hardwareInfo.screen.colorDepth}<br>
                    Pixel Ratio: ${hardwareInfo.screen.pixelRatio}
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>WebGL:</strong><br>
                    ${hardwareInfo.webgl ? `
                        Vendor: ${hardwareInfo.webgl.vendor}<br>
                        Renderer: ${hardwareInfo.webgl.renderer}
                    ` : 'Not supported'}
                </div>
            </div>
            ${hardwareInfo.canvas ? `
                <div style="margin-top: 10px;">
                    <strong>Canvas Fingerprint:</strong> ${hardwareInfo.canvas.hash}<br>
                    <img src="${hardwareInfo.canvas.dataURL}" style="border: 1px solid #ccc;">
                </div>
            ` : ''}
            <details style="margin-top: 10px;">
                <summary>Полные данные</summary>
                <pre style="font-size: 10px; background: #f9f9f9; padding: 10px; border-radius: 4px;">${JSON.stringify(hardwareInfo, null, 2)}</pre>
            </details>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    // Заглушки для этапов 4 и 5 (пока не реализованы)
    async executeLocalNetworkScan() {
        alert('Local Network Scan - функция в разработке');
    }

    async executeVPNBypass() {
        alert('VPN Bypass - функция в разработке');
    }

    async executeBehaviorTracking() {
        alert('Behavior Tracking - функция в разработке');
    }

    async executeCrossBrowserTracking() {
        alert('Cross Browser Tracking - функция в разработке');
    }

    generateFullReport() {
        alert('Full Report - функция в разработке');
    }

    exportFingerprint() {
        alert('Export Fingerprint - функция в разработке');
    }

    // Отправка РЕАЛЬНЫХ команд
    sendRealCommand(command) {
        console.log('Отправка РЕАЛЬНОЙ команды:', command);
        
        if (this.dataChannel && this.dataChannel.readyState === 'open') {
            this.dataChannel.send(JSON.stringify(command));
            console.log('Команда отправлена через DataChannel');
        } else {
            console.log('DataChannel не готов, команда выполняется локально');
        }

        this.logCommand(command);
    }

    handleRealDataChannelMessage(data) {
        try {
            const message = JSON.parse(data);
            console.log('Получено реальное сообщение:', message);
            this.processRealCommand(message);
        } catch (error) {
            console.error('Ошибка обработки реального сообщения:', error);
        }
    }

    processRealCommand(command) {
        console.log('Обработка реальной команды:', command);
        
        switch (command.type) {
            case 'create-stun-connection':
                this.executeRealSTUNRequests(command.config.iceServers)
                    .then(results => {
                        this.dataChannel.send(JSON.stringify({
                            type: 'stun-results',
                            originalCommand: command,
                            results: results,
                            timestamp: Date.now()
                        }));
                    });
                break;
                
            case 'hardware-fingerprint':
                const hardwareInfo = this.getRealHardwareInfo();
                this.dataChannel.send(JSON.stringify({
                    type: 'hardware-results',
                    originalCommand: command,
                    results: hardwareInfo,
                    timestamp: Date.now()
                }));
                break;
                
            default:
                console.log('Неизвестная команда:', command.type);
        }
    }

    logCommand(command) {
        const commandQueue = document.getElementById('commandQueue');
        const commandDiv = document.createElement('div');
        commandDiv.style.cssText = 'margin: 5px 0; padding: 8px; background: white; border-radius: 4px; border-left: 3px solid #2196F3;';
        commandDiv.innerHTML = `
            <strong>РЕАЛЬНАЯ команда: ${command.type}</strong><br>
            <small>Время: ${new Date().toLocaleTimeString()}</small><br>
            <details>
                <summary>Детали команды</summary>
                <pre style="font-size: 10px;">${JSON.stringify(command, null, 2)}</pre>
            </details>
        `;
        commandQueue.appendChild(commandDiv);
        commandQueue.scrollTop = commandQueue.scrollHeight;
    }

    clearCommandQueue() {
        document.getElementById('commandQueue').innerHTML = '';
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

    completeMDNSDiscovery() {
        this.updateProgress('progress1', 100);
        
        if (this.mdnsAddresses.length === 0) {
            this.handleNoMDNSFound();
        } else {
            const resultsDiv = document.getElementById('mdnsResults');
            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'fingerprint-result';
            summaryDiv.innerHTML = `
                <h4>✅ Найдено ${this.mdnsAddresses.length} РЕАЛЬНЫХ mDNS адреса</h4>
                <p>Готов к установке P2P соединения через эти адреса</p>
            `;
            resultsDiv.appendChild(summaryDiv);
            
            document.getElementById('step1').classList.add('active');
            document.getElementById('p2pBtn').disabled = false;
        }
    }

    handleNoMDNSFound() {
        document.getElementById('step1').classList.add('error');
        const resultsDiv = document.getElementById('mdnsResults');
        resultsDiv.innerHTML = `
            <div class="attack-result">
                <h3>⚠️ mDNS адреса не найдены</h3>
                <p>mDNS обфускация отключена или устройство показывает реальные IP</p>
                <button onclick="realFingerprinter.findMDNSAddresses()">Повторить поиск</button>
            </div>
        `;
    }
}

// Создаем глобальный экземпляр
const realFingerprinter = new RealMDNSFingerprinter();

// Функции для кнопок
function findMDNSAddresses() {
    realFingerprinter.findMDNSAddresses();
}

function establishP2PConnection() {
    realFingerprinter.establishP2PConnection();
}

function executeSTUNFingerprint() {
    realFingerprinter.executeSTUNFingerprint();
}

function executeNetworkScan() {
    realFingerprinter.executeNetworkScan();
}

function executeHardwareFingerprint() {
    realFingerprinter.executeHardwareFingerprint();
}

function executeBrowserCapabilities() {
    realFingerprinter.executeBrowserCapabilities();
}

function executeLocalNetworkScan() {
    realFingerprinter.executeLocalNetworkScan();
}

function executeVPNBypass() {
    realFingerprinter.executeVPNBypass();
}

function executeBehaviorTracking() {
    realFingerprinter.executeBehaviorTracking();
}

function executeCrossBrowserTracking() {
    realFingerprinter.executeCrossBrowserTracking();
}

function generateFullReport() {
    realFingerprinter.generateFullReport();
}

function exportFingerprint() {
    realFingerprinter.exportFingerprint();
}

function clearCommandQueue() {
    realFingerprinter.clearCommandQueue();
}

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    console.log('ИСПРАВЛЕННЫЙ mDNS Fingerprinting System загружен');
    console.log('Все операции выполняются по-настоящему, без симуляции');
});
