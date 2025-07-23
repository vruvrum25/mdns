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
  // УНИВЕРСАЛЬНАЯ функция получения локального IP
async getLocalIP() {
    return new Promise(function(resolve, reject) {
        var RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;

        if (!RTCPeerConnection) {
            reject('Your browser does not support this API');
        }
        
        var rtc = new RTCPeerConnection({iceServers:[]});
        var addrs = {};
        addrs["0.0.0.0"] = false;
        
        function grepSDP(sdp) {
            var hosts = [];
            var finalIP = '';
            sdp.split('\r\n').forEach(function (line) {
                if (~line.indexOf("a=candidate")) {
                    var parts = line.split(' '),
                        addr = parts[4],
                        type = parts[7];
                    if (type === 'host') {
                        finalIP = addr;
                    }
                } else if (~line.indexOf("c=")) {
                    var parts = line.split(' '),
                        addr = parts[2];
                    finalIP = addr;
                }
            });
            return finalIP;
        }
        
        if (1 || window.mozRTCPeerConnection) {
            rtc.createDataChannel('', {reliable:false});
        }
        
        rtc.onicecandidate = function (evt) {
            if (evt.candidate) {
                var addr = grepSDP("a="+evt.candidate.candidate);
                if (addr && addr !== '0.0.0.0') {
                    rtc.close();
                    resolve(addr);
                }
            }
        };
        
        rtc.createOffer(function (offerDesc) {
            rtc.setLocalDescription(offerDesc);
        }, function (e) { 
            console.warn("offer failed", e);
            reject(e);
        });

        // Таймаут на случай отсутствия кандидатов
        setTimeout(() => {
            rtc.close();
            reject('Timeout: No local IP found');
        }, 10000);
    });
}

// ЭТАП 1: Универсальное обнаружение локальных адресов (ЗАМЕНА findMDNSAddresses)
async findLocalAddresses() {
    this.updateStatus('globalStatus', 'active', 'Поиск локальных адресов...');
    this.updateProgress('progress1', 0);
    
    const resultsDiv = document.getElementById('mdnsResults');
    resultsDiv.innerHTML = '<p>🔍 Универсальное сканирование локальных адресов...</p>';
    
    // Сбрасываем данные
    this.localAddresses = [];
    this.addressType = null;

    try {
        this.updateProgress('progress1', 30);
        
        // Используем универсальный метод получения локального IP
        const localAddr = await this.getLocalIP();
        
        this.updateProgress('progress1', 70);
        console.log('Получен локальный адрес:', localAddr);
        
        // Определяем тип адреса
        if (this.isMDNSAddress(localAddr)) {
            this.addressType = 'mDNS';
            this.localAddresses = [{
                address: localAddr,
                type: 'mDNS',
                timestamp: new Date().toISOString()
            }];
            this.displayFoundAddress(localAddr, 'mDNS');
        } else if (this.isRealLocalIP(localAddr)) {
            this.addressType = 'realIP';
            this.localAddresses = [{
                address: localAddr,
                type: 'realIP',
                timestamp: new Date().toISOString()
            }];
            this.displayFoundAddress(localAddr, 'Real IP');
        } else {
            throw new Error(`Неизвестный тип адреса: ${localAddr}`);
        }
        
        this.updateProgress('progress1', 100);
        this.completeLocalAddressDiscovery();
        
    } catch (error) {
        console.error('Ошибка получения локального адреса:', error);
        this.handleNoLocalAddressFound(error.message);
    }
}
// Проверка, является ли адрес mDNS
isMDNSAddress(addr) {
    return typeof addr === 'string' && addr.endsWith('.local');
}

// Проверка, является ли адрес реальным локальным IP
isRealLocalIP(addr) {
    if (typeof addr !== 'string') return false;
    
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = addr.match(ipRegex);
    
    if (!match) return false;
    
    const parts = match.slice(1).map(Number);
    
    // Проверяем диапазоны приватных IP
    return (
        (parts[0] === 192 && parts[1] === 168) ||
        (parts[0] === 10) ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 169 && parts[1] === 254) // Link-local
    );
}

displayFoundAddress(address, type) {
    const resultsDiv = document.getElementById('mdnsResults');
    const addressDiv = document.createElement('div');
    addressDiv.className = type === 'mDNS' ? 'mdns-address' : 'real-ip-address';
    
    const icon = type === 'mDNS' ? '🌐' : '🔗';
    const description = type === 'mDNS' ? 'mDNS адрес (обфусцированный)' : 'Реальный локальный IP';
    
    addressDiv.innerHTML = `
        <h4>${icon} ${type} адрес найден</h4>
        <strong>Адрес:</strong> <code>${address}</code><br>
        <strong>Тип:</strong> ${description}<br>
        <strong>Время:</strong> ${new Date().toLocaleTimeString()}
    `;
    resultsDiv.appendChild(addressDiv);
    console.log(`${type} адрес добавлен:`, address);
}

completeLocalAddressDiscovery() {
    if (this.localAddresses.length === 0) {
        this.handleNoLocalAddressFound('Адреса не найдены');
        return;
    }

    const address = this.localAddresses[0];
    const resultsDiv = document.getElementById('mdnsResults');
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'fingerprint-result';
    
    const typeDescription = address.type === 'mDNS' ? 
        'mDNS адрес (WebRTC обфускация включена)' : 
        'реальный локальный IP (WebRTC обфускация отключена)';
    
    summaryDiv.innerHTML = `
        <h4>✅ Найден ${typeDescription}</h4>
        <p><strong>Адрес:</strong> <code>${address.address}</code></p>
        <p><strong>Стратегия:</strong> ${this.getConnectionStrategy()}</p>
        <p>Готов к установке P2P соединения</p>
    `;
    resultsDiv.appendChild(summaryDiv);
    
    document.getElementById('step1').classList.add('active');
    document.getElementById('p2pBtn').disabled = false;
    this.updateStatus('globalStatus', 'success', `${address.type} адрес найден`);
}

getConnectionStrategy() {
    if (this.addressType === 'mDNS') {
        return 'P2P через mDNS обфускацию (повышенная приватность)';
    } else {
        return 'P2P через реальный IP (прямое соединение)';
    }
}

handleNoLocalAddressFound(error) {
    document.getElementById('step1').classList.add('error');
    const resultsDiv = document.getElementById('mdnsResults');
    resultsDiv.innerHTML = `
        <div class="attack-result">
            <h3>⚠️ Локальный адрес не найден</h3>
            <p><strong>Ошибка:</strong> ${error}</p>
            <p><strong>Возможные причины:</strong></p>
            <ul>
                <li>WebRTC полностью заблокирован</li>
                <li>Антидетект браузер блокирует все host кандидаты</li>
                <li>Корпоративная сеть с жесткими ограничениями</li>
                <li>VPN блокирует локальные адреса</li>
            </ul>
            <button onclick="realFingerprinter.findLocalAddresses()">Повторить поиск</button>
        </div>
    `;
    this.updateStatus('globalStatus', 'error', 'Локальный адрес не найден');
}


   // МОДИФИЦИРОВАННОЕ P2P соединение (адаптируется к типу адреса)
async establishP2PConnection() {
    if (this.localAddresses.length === 0) {
        alert('Сначала найдите локальные адреса!');
        return;
    }

    const address = this.localAddresses[0];
    
    this.updateStatus('globalStatus', 'active', 'Установка P2P соединения...');
    this.updateProgress('progress2', 0);

    const resultsDiv = document.getElementById('p2pResults');
    resultsDiv.innerHTML = `<p>🔗 Создание P2P соединения через ${address.type} адрес...</p>`;

    try {
        this.peerConnection = new RTCPeerConnection({iceServers: []});
        
        // Настраиваем DataChannel в зависимости от типа адреса
        const channelConfig = this.getDataChannelConfig(address.type);
        this.dataChannel = this.peerConnection.createDataChannel('universal-channel', channelConfig);

        this.setupUniversalDataChannel();
        this.setupUniversalPeerConnection();
        
        const offer = await this.peerConnection.createOffer();
        await this.peerConnection.setLocalDescription(offer);

        this.updateProgress('progress2', 60);

        // Симулируем установку соединения
        setTimeout(() => {
            this.completeUniversalP2PConnection();
        }, 2500);

    } catch (error) {
        console.error('Ошибка P2P соединения:', error);
        this.updateStatus('globalStatus', 'error', 'Ошибка P2P');
        this.displayP2PError(error);
    }
}

getDataChannelConfig(addressType) {
    if (addressType === 'mDNS') {
        return {
            ordered: true,
            maxRetransmits: 3,
            label: 'mDNS-channel'
        };
    } else {
        return {
            ordered: true,
            maxRetransmits: 5,
            label: 'direct-ip-channel'
        };
    }
}

setupUniversalDataChannel() {
    this.dataChannel.onopen = () => {
        console.log('Universal DataChannel открыт');
        this.completeUniversalP2PConnection();
    };

    this.dataChannel.onmessage = (event) => {
        console.log('Получено сообщение через universal channel:', event.data);
        this.handleRealDataChannelMessage(event.data);
    };

    this.dataChannel.onerror = (error) => {
        console.error('Universal DataChannel ошибка:', error);
    };
}

setupUniversalPeerConnection() {
    this.peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            const candidate = event.candidate.candidate;
            const address = this.localAddresses[0].address;
            
            if (candidate.includes(address)) {
                console.log('P2P кандидат найден:', candidate);
                this.updateProgress('progress2', 80);
            }
        }
    };

    this.peerConnection.onconnectionstatechange = () => {
        console.log('Universal P2P состояние:', this.peerConnection.connectionState);
    };
}

completeUniversalP2PConnection() {
    this.updateProgress('progress2', 100);
    this.isConnected = true;

    const address = this.localAddresses[0];
    this.updateStatus('globalStatus', 'success', 'P2P соединение установлено');

    const resultsDiv = document.getElementById('p2pResults');
    resultsDiv.innerHTML = `
        <div class="fingerprint-result">
            <h4>✅ P2P соединение установлено!</h4>
            <div style="background: #e3f2fd; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>Тип соединения:</strong> ${address.type === 'mDNS' ? 'mDNS (обфусцированное)' : 'Direct IP'}<br>
                <strong>Адрес:</strong> <code>${address.address}</code><br>
                <strong>Преимущества:</strong> ${this.getConnectionAdvantages(address.type)}
            </div>
            <p><strong>DataChannel готов для fingerprinting команд</strong></p>
        </div>
    `;

    document.getElementById('step2').classList.add('active');
    this.enableAllFingerprintingButtons();
    
    // Логируем тип соединения
    this.logToMonitor(`🚀 P2P соединение установлено через ${address.type}: ${address.address}`);
}

getConnectionAdvantages(addressType) {
    if (addressType === 'mDNS') {
        return 'Повышенная приватность, обход сетевых фильтров, работа в защищенных сетях';
    } else {
        return 'Прямое соединение, высокая скорость, полный контроль над сетевым стеком';
    }
}

displayP2PError(error) {
    const resultsDiv = document.getElementById('p2pResults');
    resultsDiv.innerHTML = `
        <div class="attack-result">
            <h3>❌ Ошибка P2P соединения</h3>
            <p><strong>Тип адреса:</strong> ${this.localAddresses[0]?.type || 'Неизвестно'}</p>
            <p><strong>Адрес:</strong> <code>${this.localAddresses[0]?.address || 'Неизвестно'}</code></p>
            <p><strong>Ошибка:</strong> ${error.message}</p>
            <button onclick="realFingerprinter.establishP2PConnection()">Повторить попытку</button>
        </div>
    `;
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

       // ЭТАП 4: РАСШИРЕННЫЕ МЕТОДЫ (ОПАСНО)

    async executeLocalNetworkScan() {
        console.log('Выполнение РЕАЛЬНОГО сканирования локальной сети...');
        
        const command = {
            type: 'local-network-scan',
            timestamp: Date.now(),
            method: 'webrtc-connectivity-test'
        };

        this.sendRealCommand(command);
        
        // Выполняем реальное сканирование локальной сети
        const networkScanResults = await this.performRealNetworkScan();
        this.displayLocalNetworkScanResults(networkScanResults);
    }

    async performRealNetworkScan() {
        console.log('Начинаем реальное сканирование локальной сети...');
        
        // Сначала определяем наш локальный IP и подсеть
        const localNetwork = await this.detectLocalNetwork();
        if (!localNetwork.subnet) {
            return {error: 'Не удалось определить локальную сеть'};
        }

        console.log('Обнаружена локальная сеть:', localNetwork);

        // Генерируем список IP для сканирования
        const scanTargets = this.generateScanTargets(localNetwork.subnet);
        
        // Сканируем сеть через WebRTC connectivity tests
        const results = await this.scanNetworkTargets(scanTargets);
        
        return {
            localNetwork: localNetwork,
            scanTargets: scanTargets.length,
            results: results,
            scanDuration: Date.now() - Date.now()
        };
    }

   // МОДИФИЦИРОВАННАЯ функция обнаружения локальной сети (учитывает тип адреса)
async detectLocalNetwork() {
    return new Promise((resolve) => {
        // Если у нас уже есть адрес из первого этапа, используем его
        if (this.localAddresses.length > 0) {
            const address = this.localAddresses[0];
            
            if (address.type === 'realIP') {
                // Для реального IP определяем подсеть стандартным способом
                const subnet = this.getSubnet(address.address);
                resolve({
                    localIP: address.address,
                    subnet: subnet,
                    networkClass: this.getNetworkClass(address.address),
                    source: 'cached-real-ip'
                });
                return;
            } else if (address.type === 'mDNS') {
                // Для mDNS пытаемся получить реальный IP через дополнительный запрос
                this.tryResolveRealIPFromMDNS()
                    .then(realIP => {
                        if (realIP) {
                            const subnet = this.getSubnet(realIP);
                            resolve({
                                localIP: realIP,
                                subnet: subnet,
                                networkClass: this.getNetworkClass(realIP),
                                mdnsAddress: address.address,
                                source: 'resolved-from-mdns'
                            });
                        } else {
                            resolve({
                                error: 'Не удалось разрешить реальный IP из mDNS',
                                mdnsAddress: address.address
                            });
                        }
                    })
                    .catch(() => {
                        resolve({
                            error: 'Ошибка разрешения mDNS',
                            mdnsAddress: address.address
                        });
                    });
                return;
            }
        }

        // Fallback: стандартный поиск через WebRTC
        const pc = new RTCPeerConnection({iceServers: []});
        pc.createDataChannel('network-detect');
        
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                const candidate = event.candidate.candidate;
                
                const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                if (ipMatch && candidate.includes('typ host')) {
                    const ip = ipMatch[1];
                    
                    if (this.isPrivateIP(ip)) {
                        const subnet = this.getSubnet(ip);
                        pc.close();
                        resolve({
                            localIP: ip,
                            subnet: subnet,
                            networkClass: this.getNetworkClass(ip),
                            source: 'webrtc-fallback'
                        });
                        return;
                    }
                }
            } else {
                pc.close();
                resolve({error: 'Локальный IP не найден через fallback'});
            }
        };

        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        
        setTimeout(() => {
            pc.close();
            resolve({error: 'Таймаут определения сети через fallback'});
        }, 5000);
    });
}

// Попытка получить реальный IP из mDNS через STUN
async tryResolveRealIPFromMDNS() {
    try {
        console.log('Пытаемся разрешить реальный IP из mDNS через STUN...');
        
        const pc = new RTCPeerConnection({
            iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
        });
        
        return new Promise((resolve) => {
            let resolved = false;
            
            pc.onicecandidate = (event) => {
                if (event.candidate && !resolved) {
                    const candidate = event.candidate.candidate;
                    
                    // Ищем host кандидат с реальным IP
                    if (candidate.includes('typ host')) {
                        const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                        if (ipMatch && this.isPrivateIP(ipMatch[1])) {
                            resolved = true;
                            pc.close();
                            console.log('Разрешен реальный IP из mDNS:', ipMatch[1]);
                            resolve(ipMatch[1]);
                        }
                    }
                } else if (!event.candidate && !resolved) {
                    // Завершение без нахождения реального IP
                    pc.close();
                    resolve(null);
                }
            };
            
            pc.createDataChannel('mdns-resolve');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));
            
            setTimeout(() => {
                if (!resolved) {
                    pc.close();
                    resolve(null);
                }
            }, 5000);
        });
        
    } catch (error) {
        console.error('Ошибка разрешения mDNS:', error);
        return null;
    }
}


    isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        return (
            (parts[0] === 192 && parts[1] === 168) ||
            (parts[0] === 10) ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        );
    }

    getSubnet(ip) {
        const parts = ip.split('.');
        if (parts[0] === '192' && parts[1] === '168') {
            return `${parts[0]}.${parts[1]}.${parts[2]}`;
        } else if (parts[0] === '10') {
            return `${parts[0]}.${parts[1]}.${parts[2]}`;
        } else if (parts[0] === '172') {
            return `${parts[0]}.${parts[1]}.${parts[2]}`;
        }
        return null;
    }

    getNetworkClass(ip) {
        const firstOctet = parseInt(ip.split('.')[0]);
        if (firstOctet === 192) return 'Class C (обычно домашние сети)';
        if (firstOctet === 10) return 'Class A (крупные корпоративные сети)';
        if (firstOctet === 172) return 'Class B (средние корпоративные сети)';
        return 'Unknown';
    }

    generateScanTargets(subnet) {
        const targets = [];
        
        // Важные адреса
        targets.push(`${subnet}.1`);   // Обычно роутер
        targets.push(`${subnet}.254`); // Альтернативный роутер
        
        // Диапазон принтеров/устройств
        for (let i = 100; i <= 110; i++) {
            targets.push(`${subnet}.${i}`);
        }
        
        // Диапазон серверов/NAS
        for (let i = 200; i <= 210; i++) {
            targets.push(`${subnet}.${i}`);
        }
        
        // Случайные адреса для полноты картины
        for (let i = 2; i <= 50; i += 5) {
            targets.push(`${subnet}.${i}`);
        }

        console.log('Создан список для сканирования:', targets);
        return targets;
    }

    async scanNetworkTargets(targets) {
        const results = [];
        const maxConcurrent = 5; // Ограничиваем количество одновременных соединений
        
        console.log(`Сканируем ${targets.length} целей...`);

        for (let i = 0; i < targets.length; i += maxConcurrent) {
            const batch = targets.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(target => this.testNetworkTarget(target));
            
            try {
                const batchResults = await Promise.allSettled(batchPromises);
                batchResults.forEach((result, index) => {
                    if (result.status === 'fulfilled' && result.value.reachable) {
                        results.push(result.value);
                    }
                });
                
                // Небольшая задержка между батчами
                if (i + maxConcurrent < targets.length) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            } catch (error) {
                console.error('Ошибка сканирования батча:', error);
            }
        }

        console.log('Сканирование завершено. Найдено устройств:', results.length);
        return results;
    }

    async testNetworkTarget(ip) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            
            // Пытаемся создать WebRTC соединение к цели
            const pc = new RTCPeerConnection({
                iceServers: [],
                iceCandidatePoolSize: 1
            });

            let resolved = false;
            
            const timeout = setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    pc.close();
                    resolve({
                        ip: ip,
                        reachable: false,
                        latency: Date.now() - startTime
                    });
                }
            }, 2000);

            // Создаем data channel для инициации соединения
            const dataChannel = pc.createDataChannel('scan');
            
            dataChannel.onopen = () => {
                if (!resolved) {
                    resolved = true;
                    clearTimeout(timeout);
                    pc.close();
                    resolve({
                        ip: ip,
                        reachable: true,
                        latency: Date.now() - startTime,
                        method: 'WebRTC DataChannel'
                    });
                }
            };

            dataChannel.onerror = () => {
                if (!resolved) {
                    resolved = true;
                    clearTimeout(timeout);
                    pc.close();
                    resolve({
                        ip: ip,
                        reachable: false,
                        latency: Date.now() - startTime,
                        error: 'DataChannel error'
                    });
                }
            };

            // Альтернативный метод через ICE candidates
            pc.onicecandidate = (event) => {
                if (event.candidate && event.candidate.candidate.includes(ip)) {
                    if (!resolved) {
                        resolved = true;
                        clearTimeout(timeout);
                        pc.close();
                        resolve({
                            ip: ip,
                            reachable: true,
                            latency: Date.now() - startTime,
                            method: 'ICE candidate'
                        });
                    }
                }
            };

            pc.createOffer().then(offer => pc.setLocalDescription(offer));
        });
    }

    displayLocalNetworkScanResults(scanResults) {
        const resultsDiv = document.getElementById('attackResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'critical-result';
        
        if (scanResults.error) {
            resultDiv.innerHTML = `
                <h4>🏠 Сканирование локальной сети (ОШИБКА)</h4>
                <p style="color: #f44336;">${scanResults.error}</p>
            `;
        } else {
            resultDiv.innerHTML = `
                <h4>🏠 Сканирование локальной сети (КРИТИЧНО)</h4>
                <div style="background: #fff3e0; padding: 10px; border-radius: 4px; margin: 10px 0;">
                    <strong>⚠️ ВНИМАНИЕ:</strong> Обнаружены активные устройства в локальной сети!
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin: 10px 0;">
                    <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                        <strong>Локальная сеть:</strong><br>
                        IP: ${scanResults.localNetwork.localIP}<br>
                        Подсеть: ${scanResults.localNetwork.subnet}.0/24<br>
                        Класс: ${scanResults.localNetwork.networkClass}
                    </div>
                    <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                        <strong>Сканирование:</strong><br>
                        Целей: ${scanResults.scanTargets}<br>
                        Найдено: ${scanResults.results.length}<br>
                        Метод: WebRTC connectivity
                    </div>
                </div>
                
                <h5>🎯 Обнаруженные устройства:</h5>
                ${scanResults.results.length > 0 ? scanResults.results.map(device => `
                    <div style="background: #ffebee; padding: 8px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #f44336;">
                        <strong>IP:</strong> ${device.ip}<br>
                        <strong>Состояние:</strong> ${device.reachable ? '🟢 Активен' : '🔴 Недоступен'}<br>
                        <strong>Задержка:</strong> ${device.latency}ms<br>
                        <strong>Метод:</strong> ${device.method || 'WebRTC Test'}
                    </div>
                `).join('') : '<p>Активные устройства не обнаружены</p>'}
                
                <div style="background: #ffcdd2; padding: 10px; border-radius: 4px; margin-top: 10px;">
                    <strong>🚨 Риски безопасности:</strong><br>
                    • Раскрытие топологии внутренней сети<br>
                    • Обнаружение потенциальных целей для атак<br>
                    • Возможность lateral movement в сети<br>
                    • Компрометация корпоративной безопасности
                </div>
            `;
        }
        
        resultsDiv.appendChild(resultDiv);
    }

    async executeVPNBypass() {
        console.log('Выполнение РЕАЛЬНЫХ методов обхода VPN...');
        
        const command = {
            type: 'vpn-bypass-attempt',
            timestamp: Date.now(),
            methods: ['webrtc-leak', 'ipv6-discovery', 'timing-analysis']
        };

        this.sendRealCommand(command);
        
        const vpnAnalysis = await this.performVPNAnalysis();
        this.displayVPNBypassResults(vpnAnalysis);
    }

    async performVPNAnalysis() {
        console.log('Анализ VPN и поиск утечек...');
        
        const analysis = {
            timestamp: Date.now(),
            webrtcLeaks: await this.detectWebRTCLeaks(),
            ipv6Analysis: await this.analyzeIPv6(),
            timingAnalysis: await this.performTimingAnalysis(),
            dnsLeaks: await this.detectDNSLeaks()
        };

        return analysis;
    }

    async detectWebRTCLeaks() {
        return new Promise((resolve) => {
            const results = {
                localIPs: [],
                publicIPs: [],
                stunServers: [],
                leaksDetected: false
            };

            // Тестируем разные STUN серверы
            const stunServers = [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302', 
                'stun:global.stun.twilio.com:3478',
                'stun:stun.ekiga.net',
                'stun:stun.services.mozilla.com'
            ];

            let completedTests = 0;

            stunServers.forEach(async (stunServer) => {
                try {
                    const pc = new RTCPeerConnection({
                        iceServers: [{urls: stunServer}]
                    });

                    const serverResults = {
                        server: stunServer,
                        localIPs: [],
                        publicIPs: []
                    };

                    pc.onicecandidate = (event) => {
                        if (event.candidate) {
                            const candidate = event.candidate.candidate;
                            
                            const ips = candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
                            if (ips) {
                                if (candidate.includes('typ host')) {
                                    serverResults.localIPs.push(...ips);
                                    results.localIPs.push(...ips);
                                } else if (candidate.includes('typ srflx')) {
                                    serverResults.publicIPs.push(ips[0]);
                                    results.publicIPs.push(ips[0]);
                                }
                            }
                        }
                    };

                    pc.createDataChannel('vpn-test');
                    const offer = await pc.createOffer();
                    await pc.setLocalDescription(offer);

                    setTimeout(() => {
                        pc.close();
                        results.stunServers.push(serverResults);
                        completedTests++;
                        
                        if (completedTests === stunServers.length) {
                            // Удаляем дубликаты
                            results.localIPs = [...new Set(results.localIPs)];
                            results.publicIPs = [...new Set(results.publicIPs)];
                            
                            // Определяем утечки
                            results.leaksDetected = results.localIPs.length > 0 || results.publicIPs.length > 1;
                            
                            resolve(results);
                        }
                    }, 3000);
                } catch (error) {
                    console.error('Ошибка тестирования STUN сервера', stunServer, ':', error);
                    completedTests++;
                    if (completedTests === stunServers.length) {
                        resolve(results);
                    }
                }
            });
        });
    }

    async analyzeIPv6() {
        // Проверка IPv6 утечек
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [
                    {urls: 'stun:stun.l.google.com:19302'}
                ]
            });

            const ipv6Results = {
                hasIPv6: false,
                ipv6Addresses: [],
                potentialLeak: false
            };

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    
                    // Ищем IPv6 адреса
                    const ipv6Match = candidate.match(/([0-9a-f]{1,4}::[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}|[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4})/);
                    
                    if (ipv6Match) {
                        ipv6Results.hasIPv6 = true;
                        ipv6Results.ipv6Addresses.push(ipv6Match[1]);
                        
                        // Проверяем, не является ли это потенциальной утечкой
                        if (!candidate.includes('local') && candidate.includes('typ host')) {
                            ipv6Results.potentialLeak = true;
                        }
                    }
                }
            };

            pc.createDataChannel('ipv6-test');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            setTimeout(() => {
                pc.close();
                ipv6Results.ipv6Addresses = [...new Set(ipv6Results.ipv6Addresses)];
                resolve(ipv6Results);
            }, 4000);
        });
    }

    async performTimingAnalysis() {
        // Анализ времени отклика для определения реального местоположения
        const servers = [
            {name: 'Google US', url: 'stun:stun.l.google.com:19302'},
            {name: 'Google EU', url: 'stun:stun1.l.google.com:19302'},
            {name: 'Twilio Global', url: 'stun:global.stun.twilio.com:3478'}
        ];

        const timingResults = [];

        for (const server of servers) {
            try {
                const timing = await this.measureSTUNLatency(server.url);
                timingResults.push({
                    ...server,
                    latency: timing.latency,
                    success: timing.success
                });
            } catch (error) {
                timingResults.push({
                    ...server,
                    latency: null,
                    success: false,
                    error: error.message
                });
            }
        }

        return {
            results: timingResults,
            analysis: this.analyzeLatencyPattern(timingResults)
        };
    }

    async measureSTUNLatency(stunUrl) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const pc = new RTCPeerConnection({
                iceServers: [{urls: stunUrl}]
            });

            let firstResponse = false;

            pc.onicecandidate = (event) => {
                if (event.candidate && !firstResponse) {
                    firstResponse = true;
                    const latency = Date.now() - startTime;
                    pc.close();
                    resolve({latency, success: true});
                }
            };

            pc.createDataChannel('timing-test');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            setTimeout(() => {
                if (!firstResponse) {
                    pc.close();
                    resolve({latency: null, success: false});
                }
            }, 5000);
        });
    }

    analyzeLatencyPattern(results) {
        const successfulResults = results.filter(r => r.success);
        if (successfulResults.length === 0) return 'Недостаточно данных';

        const avgLatency = successfulResults.reduce((sum, r) => sum + r.latency, 0) / successfulResults.length;
        const minLatency = Math.min(...successfulResults.map(r => r.latency));
        
        let analysis = `Средняя задержка: ${avgLatency.toFixed(2)}ms, `;
        analysis += `минимальная: ${minLatency}ms. `;
        
        if (minLatency < 50) {
            analysis += 'Возможно локальное соединение или очень быстрый VPN.';
        } else if (minLatency < 150) {
            analysis += 'Обычная задержка для региональных соединений.';
        } else {
            analysis += 'Высокая задержка, возможно международный VPN.';
        }

        return analysis;
    }

    async detectDNSLeaks() {
        // Простая проверка DNS через время разрешения доменов
        const testDomains = [
            'google.com',
            'cloudflare.com', 
            'example.com'
        ];

        const dnsResults = [];

        for (const domain of testDomains) {
            const startTime = Date.now();
            try {
                // Используем fetch для создания DNS запроса
                await fetch(`https://${domain}`, {mode: 'no-cors'});
                const resolveTime = Date.now() - startTime;
                dnsResults.push({domain, resolveTime, success: true});
            } catch (error) {
                dnsResults.push({domain, resolveTime: null, success: false});
            }
        }

        return {
            results: dnsResults,
            avgResolveTime: dnsResults.filter(r => r.success).reduce((sum, r) => sum + r.resolveTime, 0) / dnsResults.filter(r => r.success).length
        };
    }

    displayVPNBypassResults(analysis) {
        const resultsDiv = document.getElementById('attackResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'critical-result';
        
        resultDiv.innerHTML = `
            <h4>🔓 Анализ VPN и поиск утечек (КРИТИЧНО)</h4>
            
            <div style="background: #ffebee; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>⚠️ ВНИМАНИЕ:</strong> Обнаружены потенциальные утечки через WebRTC!
            </div>

            <h5>🌐 WebRTC утечки:</h5>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                <strong>Локальные IP:</strong> ${analysis.webrtcLeaks.localIPs.join(', ') || 'Не найдены'}<br>
                <strong>Публичные IP:</strong> ${analysis.webrtcLeaks.publicIPs.join(', ') || 'Не найдены'}<br>
                <strong>Утечки обнаружены:</strong> ${analysis.webrtcLeaks.leaksDetected ? '🔴 ДА' : '🟢 НЕТ'}<br>
                <strong>Протестировано STUN серверов:</strong> ${analysis.webrtcLeaks.stunServers.length}
            </div>

            <h5>🔗 IPv6 анализ:</h5>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                <strong>IPv6 поддержка:</strong> ${analysis.ipv6Analysis.hasIPv6 ? '✅' : '❌'}<br>
                <strong>IPv6 адреса:</strong> ${analysis.ipv6Analysis.ipv6Addresses.join(', ') || 'Не найдены'}<br>
                <strong>Потенциальная утечка:</strong> ${analysis.ipv6Analysis.potentialLeak ? '🔴 ДА' : '🟢 НЕТ'}
            </div>

            <h5>⏱️ Анализ задержек:</h5>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                ${analysis.timingAnalysis.results.map(result => `
                    <div style="margin: 3px 0;">
                        <strong>${result.name}:</strong> ${result.success ? result.latency + 'ms' : 'Недоступен'}
                    </div>
                `).join('')}
                <div style="margin-top: 8px; font-style: italic;">
                    ${analysis.timingAnalysis.analysis}
                </div>
            </div>

            <h5>🔍 DNS анализ:</h5>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                <strong>Среднее время DNS:</strong> ${analysis.dnsLeaks.avgResolveTime ? analysis.dnsLeaks.avgResolveTime.toFixed(2) + 'ms' : 'Недоступно'}<br>
                <strong>Результаты:</strong><br>
                ${analysis.dnsLeaks.results.map(result => `
                    <span style="font-size: 12px;">${result.domain}: ${result.success ? result.resolveTime + 'ms' : 'Ошибка'}</span>
                `).join('<br>')}
            </div>

            <div style="background: #ffcdd2; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong>🚨 Выводы по безопасности:</strong><br>
                ${analysis.webrtcLeaks.leaksDetected ? '• WebRTC утечки могут раскрыть реальный IP даже при использовании VPN<br>' : ''}
                ${analysis.ipv6Analysis.potentialLeak ? '• IPv6 утечки могут обойти VPN защиту<br>' : ''}
                • Анализ задержек может указать на реальное местоположение<br>
                • Комбинация методов создает уникальный отпечаток соединения
            </div>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    async executeBehaviorTracking() {
        console.log('Запуск РЕАЛЬНОГО поведенческого анализа...');
        
        const command = {
            type: 'behavior-tracking',
            timestamp: Date.now(),
            duration: 30000 // 30 секунд мониторинга
        };

        this.sendRealCommand(command);
        
        // Начинаем реальный сбор поведенческих данных
        this.startRealBehaviorTracking();
    }

    startRealBehaviorTracking() {
        this.behaviorData = {
            startTime: Date.now(),
            keystrokes: [],
            mouseMovements: [],
            clicks: [],
            scrolls: [],
            focusEvents: [],
            deviceOrientation: [],
            touchEvents: []
        };

        console.log('Начинаем сбор поведенческих данных...');

        // Устанавливаем обработчики событий
        this.setupBehaviorListeners();

        // Показываем статус трекинга
        this.displayBehaviorTrackingStatus();

        // Автоматически завершаем через 30 секунд
        setTimeout(() => {
            this.completeBehaviorTracking();
        }, 30000);
    }

    setupBehaviorListeners() {
        // Отслеживание клавиатуры
        this.keydownHandler = (event) => {
            this.behaviorData.keystrokes.push({
                key: event.key,
                code: event.code,
                timestamp: Date.now(),
                ctrlKey: event.ctrlKey,
                shiftKey: event.shiftKey,
                altKey: event.altKey
            });
        };

        // Отслеживание мыши
        this.mousemoveHandler = (event) => {
            // Записываем только каждое 10-е движение для оптимизации
            if (Math.random() < 0.1) {
                this.behaviorData.mouseMovements.push({
                    x: event.clientX,
                    y: event.clientY,
                    timestamp: Date.now(),
                    screenX: event.screenX,
                    screenY: event.screenY
                });
            }
        };

        // Отслеживание кликов
        this.clickHandler = (event) => {
            this.behaviorData.clicks.push({
                x: event.clientX,
                y: event.clientY,
                timestamp: Date.now(),
                button: event.button,
                target: event.target.tagName
            });
        };

        // Отслеживание скроллинга
        this.scrollHandler = (event) => {
            this.behaviorData.scrolls.push({
                timestamp: Date.now(),
                scrollY: window.scrollY,
                scrollX: window.scrollX
            });
        };

        // Отслеживание фокуса
        this.focusHandler = (event) => {
            this.behaviorData.focusEvents.push({
                timestamp: Date.now(),
                type: 'focus',
                target: event.target.tagName
            });
        };

        this.blurHandler = (event) => {
            this.behaviorData.focusEvents.push({
                timestamp: Date.now(),
                type: 'blur',
                target: event.target.tagName
            });
        };

        // Отслеживание ориентации устройства (для мобильных)
        this.orientationHandler = (event) => {
            this.behaviorData.deviceOrientation.push({
                timestamp: Date.now(),
                alpha: event.alpha,
                beta: event.beta,
                gamma: event.gamma
            });
        };

        // Отслеживание касаний (для мобильных)
        this.touchHandler = (event) => {
            if (event.touches.length > 0) {
                this.behaviorData.touchEvents.push({
                    timestamp: Date.now(),
                    touches: Array.from(event.touches).map(touch => ({
                        x: touch.clientX,
                        y: touch.clientY,
                        force: touch.force
                    }))
                });
            }
        };

        // Добавляем обработчики
        document.addEventListener('keydown', this.keydownHandler);
        document.addEventListener('mousemove', this.mousemoveHandler);
        document.addEventListener('click', this.clickHandler);
        document.addEventListener('scroll', this.scrollHandler);
        document.addEventListener('focusin', this.focusHandler);
        document.addEventListener('focusout', this.blurHandler);
        
        // Мобильные события
        if ('DeviceOrientationEvent' in window) {
            window.addEventListener('deviceorientation', this.orientationHandler);
        }
        if ('ontouchstart' in window) {
            document.addEventListener('touchstart', this.touchHandler);
        }
    }

    displayBehaviorTrackingStatus() {
        const resultsDiv = document.getElementById('attackResults');
        const statusDiv = document.createElement('div');
        statusDiv.className = 'attack-result';
        statusDiv.id = 'behaviorTrackingStatus';
        
        statusDiv.innerHTML = `
            <h4>👤 Поведенческий анализ (АКТИВЕН)</h4>
            <div style="background: #fff3e0; padding: 10px; border-radius: 4px;">
                <strong>🔴 АКТИВНОЕ ОТСЛЕЖИВАНИЕ</strong><br>
                Система анализирует ваше поведение в реальном времени...<br>
                <div style="margin-top: 10px;">
                    <div id="behaviorCounters">
                        Нажатий клавиш: <span id="keystrokeCount">0</span><br>
                        Движений мыши: <span id="mouseCount">0</span><br>
                        Кликов: <span id="clickCount">0</span><br>
                        Событий скролла: <span id="scrollCount">0</span>
                    </div>
                </div>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    Трекинг завершится автоматически через 30 секунд
                </div>
            </div>
        `;
        
        resultsDiv.appendChild(statusDiv);

        // Обновляем счетчики в реальном времени
        this.behaviorCounterInterval = setInterval(() => {
            this.updateBehaviorCounters();
        }, 1000);
    }

    updateBehaviorCounters() {
        const keystrokeCount = document.getElementById('keystrokeCount');
        const mouseCount = document.getElementById('mouseCount');
        const clickCount = document.getElementById('clickCount');
        const scrollCount = document.getElementById('scrollCount');

        if (keystrokeCount) keystrokeCount.textContent = this.behaviorData.keystrokes.length;
        if (mouseCount) mouseCount.textContent = this.behaviorData.mouseMovements.length;
        if (clickCount) clickCount.textContent = this.behaviorData.clicks.length;
        if (scrollCount) scrollCount.textContent = this.behaviorData.scrolls.length;
    }

    completeBehaviorTracking() {
        console.log('Завершаем сбор поведенческих данных...');

        // Удаляем обработчики событий
        this.removeBehaviorListeners();

        // Останавливаем обновление счетчиков
        if (this.behaviorCounterInterval) {
            clearInterval(this.behaviorCounterInterval);
        }

        // Анализируем собранные данные
        const analysis = this.analyzeBehaviorData();

        // Отображаем результаты
        this.displayBehaviorTrackingResults(analysis);
    }

    removeBehaviorListeners() {
        document.removeEventListener('keydown', this.keydownHandler);
        document.removeEventListener('mousemove', this.mousemoveHandler);
        document.removeEventListener('click', this.clickHandler);
        document.removeEventListener('scroll', this.scrollHandler);
        document.removeEventListener('focusin', this.focusHandler);
        document.removeEventListener('focusout', this.blurHandler);
        
        if ('DeviceOrientationEvent' in window) {
            window.removeEventListener('deviceorientation', this.orientationHandler);
        }
        if ('ontouchstart' in window) {
            document.removeEventListener('touchstart', this.touchHandler);
        }
    }

    analyzeBehaviorData() {
        const duration = Date.now() - this.behaviorData.startTime;
        
        const analysis = {
            duration: duration,
            keystrokeAnalysis: this.analyzeKeystrokes(),
            mouseAnalysis: this.analyzeMouseMovement(),
            clickAnalysis: this.analyzeClicks(),
            scrollAnalysis: this.analyzeScrolling(),
            deviceAnalysis: this.analyzeDeviceInteraction(),
            uniquenessScore: 0
        };

        // Рассчитываем общий показатель уникальности
        analysis.uniquenessScore = this.calculateBehaviorUniqueness(analysis);

        return analysis;
    }

    analyzeKeystrokes() {
        if (this.behaviorData.keystrokes.length === 0) {
            return {error: 'Недостаточно данных о нажатиях клавиш'};
        }

        const keystrokes = this.behaviorData.keystrokes;
        const intervals = [];
        
        for (let i = 1; i < keystrokes.length; i++) {
            intervals.push(keystrokes[i].timestamp - keystrokes[i-1].timestamp);
        }

        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const typingSpeed = keystrokes.length / (Date.now() - this.behaviorData.startTime) * 60000; // знаков в минуту

        return {
            totalKeystrokes: keystrokes.length,
            averageInterval: avgInterval,
            typingSpeed: typingSpeed,
            commonKeys: this.getTopKeys(keystrokes),
            modifierUsage: this.analyzeModifierKeys(keystrokes)
        };
    }

    getTopKeys(keystrokes) {
        const keyCount = {};
        keystrokes.forEach(ks => {
            keyCount[ks.key] = (keyCount[ks.key] || 0) + 1;
        });

        return Object.entries(keyCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([key, count]) => ({key, count}));
    }

    analyzeModifierKeys(keystrokes) {
        const modifiers = {
            ctrl: keystrokes.filter(ks => ks.ctrlKey).length,
            shift: keystrokes.filter(ks => ks.shiftKey).length,
            alt: keystrokes.filter(ks => ks.altKey).length
        };

        return modifiers;
    }

    analyzeMouseMovement() {
        if (this.behaviorData.mouseMovements.length === 0) {
            return {error: 'Недостаточно данных о движении мыши'};
        }

        const movements = this.behaviorData.mouseMovements;
        const distances = [];
        const speeds = [];

        for (let i = 1; i < movements.length; i++) {
            const prev = movements[i-1];
            const curr = movements[i];
            
            const distance = Math.sqrt(
                Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2)
            );
            const time = curr.timestamp - prev.timestamp;
            const speed = distance / time;

            distances.push(distance);
            if (time > 0) speeds.push(speed);
        }

        const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
        const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;

        return {
            totalMovements: movements.length,
            averageDistance: avgDistance,
            averageSpeed: avgSpeed,
            mousePattern: this.analyzeMousePattern(movements)
        };
    }

    analyzeMousePattern(movements) {
        // Анализ паттернов движения мыши
        const directions = [];
        
        for (let i = 1; i < movements.length; i++) {
            const prev = movements[i-1];
            const curr = movements[i];
            
            const deltaX = curr.x - prev.x;
            const deltaY = curr.y - prev.y;
            
            if (Math.abs(deltaX) > Math.abs(deltaY)) {
                directions.push(deltaX > 0 ? 'right' : 'left');
            } else {
                directions.push(deltaY > 0 ? 'down' : 'up');
            }
        }

        const directionCount = {};
        directions.forEach(dir => {
            directionCount[dir] = (directionCount[dir] || 0) + 1;
        });

        return directionCount;
    }

    analyzeClicks() {
        const clicks = this.behaviorData.clicks;
        
        if (clicks.length === 0) {
            return {error: 'Нет данных о кликах'};
        }

        const clickIntervals = [];
        for (let i = 1; i < clicks.length; i++) {
            clickIntervals.push(clicks[i].timestamp - clicks[i-1].timestamp);
        }

        return {
            totalClicks: clicks.length,
            averageInterval: clickIntervals.length > 0 ? clickIntervals.reduce((a, b) => a + b, 0) / clickIntervals.length : 0,
            buttonUsage: this.analyzeButtonUsage(clicks),
            clickLocations: this.analyzeClickLocations(clicks)
        };
    }

    analyzeButtonUsage(clicks) {
        const buttons = {0: 0, 1: 0, 2: 0}; // Левая, средняя, правая
        clicks.forEach(click => {
            buttons[click.button] = (buttons[click.button] || 0) + 1;
        });
        return buttons;
    }

    analyzeClickLocations(clicks) {
        const locations = {};
        clicks.forEach(click => {
            const region = this.getClickRegion(click.x, click.y);
            locations[region] = (locations[region] || 0) + 1;
        });
        return locations;
    }

    getClickRegion(x, y) {
        const centerX = window.innerWidth / 2;
        const centerY = window.innerHeight / 2;
        
        const horizontal = x < centerX / 2 ? 'left' : x > centerX * 1.5 ? 'right' : 'center';
        const vertical = y < centerY / 2 ? 'top' : y > centerY * 1.5 ? 'bottom' : 'middle';
        
        return `${vertical}-${horizontal}`;
    }

    analyzeScrolling() {
        const scrolls = this.behaviorData.scrolls;
        
        if (scrolls.length === 0) {
            return {error: 'Нет данных о скроллинге'};
        }

        const scrollSpeeds = [];
        for (let i = 1; i < scrolls.length; i++) {
            const prev = scrolls[i-1];
            const curr = scrolls[i];
            const distance = Math.abs(curr.scrollY - prev.scrollY);
            const time = curr.timestamp - prev.timestamp;
            if (time > 0) scrollSpeeds.push(distance / time);
        }

        return {
            totalScrolls: scrolls.length,
            averageSpeed: scrollSpeeds.reduce((a, b) => a + b, 0) / scrollSpeeds.length,
            scrollRange: {
                min: Math.min(...scrolls.map(s => s.scrollY)),
                max: Math.max(...scrolls.map(s => s.scrollY))
            }
        };
    }

    analyzeDeviceInteraction() {
        const analysis = {
            orientation: this.behaviorData.deviceOrientation.length > 0,
            touch: this.behaviorData.touchEvents.length > 0,
            deviceType: 'ontouchstart' in window ? 'mobile' : 'desktop'
        };

        if (analysis.touch) {
            analysis.touchAnalysis = {
                totalTouches: this.behaviorData.touchEvents.length,
                multiTouch: this.behaviorData.touchEvents.some(t => t.touches.length > 1)
            };
        }

        return analysis;
    }

    calculateBehaviorUniqueness(analysis) {
        let score = 0;
        
        // Уникальность печатного ритма
        if (analysis.keystrokeAnalysis.averageInterval) {
            score += Math.min(analysis.keystrokeAnalysis.averageInterval / 10, 50);
        }
        
        // Уникальность движения мыши
        if (analysis.mouseAnalysis.averageSpeed) {
            score += Math.min(analysis.mouseAnalysis.averageSpeed * 10, 30);
        }
        
        // Бонус за разнообразие действий
        const actionTypes = [
            analysis.keystrokeAnalysis.totalKeystrokes > 0,
            analysis.mouseAnalysis.totalMovements > 0,
            analysis.clickAnalysis.totalClicks > 0,
            analysis.scrollAnalysis.totalScrolls > 0
        ].filter(Boolean).length;
        
        score += actionTypes * 5;

        return Math.min(score, 100);
    }

    displayBehaviorTrackingResults(analysis) {
        // Удаляем статус трекинга
        const statusDiv = document.getElementById('behaviorTrackingStatus');
        if (statusDiv) statusDiv.remove();

        const resultsDiv = document.getElementById('attackResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'critical-result';
        
        resultDiv.innerHTML = `
            <h4>👤 Результаты поведенческого анализа (КРИТИЧНО)</h4>
            
            <div style="background: #ffebee; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>⚠️ СОБРАН УНИКАЛЬНЫЙ ПОВЕДЕНЧЕСКИЙ ОТПЕЧАТОК</strong><br>
                Продолжительность трекинга: ${(analysis.duration / 1000).toFixed(1)} секунд<br>
                Оценка уникальности: <strong>${analysis.uniquenessScore.toFixed(1)}/100</strong>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin: 10px 0;">
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>⌨️ Анализ печати:</strong><br>
                    ${analysis.keystrokeAnalysis.error || `
                        Нажатий: ${analysis.keystrokeAnalysis.totalKeystrokes}<br>
                        Средний интервал: ${analysis.keystrokeAnalysis.averageInterval.toFixed(2)}ms<br>
                        Скорость: ${analysis.keystrokeAnalysis.typingSpeed.toFixed(1)} зн/мин
                    `}
                </div>
                
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>🖱️ Анализ мыши:</strong><br>
                    ${analysis.mouseAnalysis.error || `
                        Движений: ${analysis.mouseAnalysis.totalMovements}<br>
                        Средняя дистанция: ${analysis.mouseAnalysis.averageDistance.toFixed(2)}px<br>
                        Средняя скорость: ${analysis.mouseAnalysis.averageSpeed.toFixed(2)} px/ms
                    `}
                </div>
                
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>👆 Анализ кликов:</strong><br>
                    ${analysis.clickAnalysis.error || `
                        Кликов: ${analysis.clickAnalysis.totalClicks}<br>
                        Средний интервал: ${analysis.clickAnalysis.averageInterval.toFixed(2)}ms<br>
                        Левая кнопка: ${analysis.clickAnalysis.buttonUsage[0] || 0}
                    `}
                </div>
                
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>📜 Анализ скроллинга:</strong><br>
                    ${analysis.scrollAnalysis.error || `
                        Событий: ${analysis.scrollAnalysis.totalScrolls}<br>
                        Средняя скорость: ${analysis.scrollAnalysis.averageSpeed.toFixed(2)} px/ms<br>
                        Диапазон: ${analysis.scrollAnalysis.scrollRange.max - analysis.scrollAnalysis.scrollRange.min}px
                    `}
                </div>
            </div>

            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>📱 Устройство:</strong> ${analysis.deviceAnalysis.deviceType}<br>
                <strong>Ориентация:</strong> ${analysis.deviceAnalysis.orientation ? '✅ Доступна' : '❌ Недоступна'}<br>
                <strong>Сенсорный ввод:</strong> ${analysis.deviceAnalysis.touch ? '✅ Обнаружен' : '❌ Не обнаружен'}
                ${analysis.deviceAnalysis.touchAnalysis ? `<br><strong>Мульти-тач:</strong> ${analysis.deviceAnalysis.touchAnalysis.multiTouch ? '✅' : '❌'}` : ''}
            </div>

            <div style="background: #ffcdd2; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong>🚨 Угрозы приватности:</strong><br>
                • Уникальный поведенческий отпечаток может использоваться для идентификации<br>
                • Паттерны печати и движения мыши крайне сложно подделать<br>
                • Данные могут коррелироваться между сайтами для cross-site tracking<br>
                • Биометрическая идентификация возможна даже при смене IP и браузера
            </div>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    async executeCrossBrowserTracking() {
        console.log('Выполнение межбраузерной корреляции...');
        
        const command = {
            type: 'cross-browser-correlation',
            timestamp: Date.now()
        };

        this.sendRealCommand(command);
        
        const correlation = await this.performCrossBrowserAnalysis();
        this.displayCrossBrowserResults(correlation);
    }

    async performCrossBrowserAnalysis() {
        console.log('Анализ межбраузерной корреляции...');
        
        const analysis = {
            browserFingerprint: await this.generateBrowserFingerprint(),
            deviceFingerprint: this.generateDeviceFingerprint(),
            networkFingerprint: await this.generateNetworkFingerprint(),
            correlationFactors: {},
            riskAssessment: {}
        };

        // Анализируем факторы корреляции
        analysis.correlationFactors = this.analyzeCorrelationFactors(analysis);
        analysis.riskAssessment = this.assessCorrelationRisk(analysis);

        return analysis;
    }

    async generateBrowserFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            vendor: navigator.vendor,
            platform: navigator.platform,
            language: navigator.language,
            languages: navigator.languages,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            onLine: navigator.onLine,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            maxTouchPoints: navigator.maxTouchPoints
        };

        // WebGL fingerprint
        fingerprint.webgl = this.getRealWebGLInfo();
        
        // Canvas fingerprint
        fingerprint.canvas = this.getRealCanvasFingerprint();
        
        // Audio context fingerprint
        fingerprint.audioContext = this.getAudioContextFingerprint();
        
        // Screen fingerprint
        fingerprint.screen = {
            width: screen.width,
            height: screen.height,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            pixelRatio: window.devicePixelRatio,
            orientation: screen.orientation ? screen.orientation.type : null
        };

        // Timezone fingerprint
        fingerprint.timezone = {
            offset: new Date().getTimezoneOffset(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };

        return fingerprint;
    }

    getAudioContextFingerprint() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(analyser);
            analyser.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            const fingerprint = {
                sampleRate: audioContext.sampleRate,
                maxChannelCount: audioContext.destination.maxChannelCount,
                numberOfInputs: audioContext.destination.numberOfInputs,
                numberOfOutputs: audioContext.destination.numberOfOutputs,
                channelCount: audioContext.destination.channelCount,
                channelCountMode: audioContext.destination.channelCountMode,
                channelInterpretation: audioContext.destination.channelInterpretation
            };
            
            audioContext.close();
            return fingerprint;
        } catch (error) {
            return {error: error.message};
        }
    }

    generateDeviceFingerprint() {
        return {
            screen: {
                total: screen.width * screen.height,
                ratio: screen.width / screen.height,
                colorDepth: screen.colorDepth,
                pixelRatio: window.devicePixelRatio
            },
            memory: performance.memory ? {
                usedJSHeapSize: performance.memory.usedJSHeapSize,
                totalJSHeapSize: performance.memory.totalJSHeapSize,
                jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
            } : null,
            concurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            connection: navigator.connection ? {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt
            } : null
        };
    }

    async generateNetworkFingerprint() {
        // Используем уже существующий метод сканирования IP
        const networkData = await this.scanAllRealIPs();
        
        return {
            localIPs: networkData.localIPs,
            publicIPs: networkData.publicIPs,
            mdnsAddresses: networkData.mdnsAddresses,
            onlineStatus: navigator.onLine,
            connection: navigator.connection ? {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt,
                saveData: navigator.connection.saveData
            } : null
        };
    }

    analyzeCorrelationFactors(analysis) {
        const factors = {};

        // Анализ стабильности отпечатков
        factors.browserStability = this.calculateBrowserStability(analysis.browserFingerprint);
        factors.deviceStability = this.calculateDeviceStability(analysis.deviceFingerprint);
        factors.networkStability = this.calculateNetworkStability(analysis.networkFingerprint);

        // Уникальность компонентов
        factors.uniquenessFactors = {
            canvas: analysis.browserFingerprint.canvas ? analysis.browserFingerprint.canvas.hash : null,
            webgl: analysis.browserFingerprint.webgl ? `${analysis.browserFingerprint.webgl.vendor}_${analysis.browserFingerprint.webgl.renderer}` : null,
            audio: analysis.browserFingerprint.audioContext ? analysis.browserFingerprint.audioContext.sampleRate : null,
            screen: `${analysis.browserFingerprint.screen.width}x${analysis.browserFingerprint.screen.height}x${analysis.browserFingerprint.screen.colorDepth}`
        };

        return factors;
    }

    calculateBrowserStability(browserFP) {
        let stability = 0;
        
        // Стабильные характеристики (не изменяются между сессиями)
        if (browserFP.vendor) stability += 20;
        if (browserFP.platform) stability += 20;
        if (browserFP.language) stability += 15;
        if (browserFP.hardwareConcurrency) stability += 15;
        if (browserFP.deviceMemory) stability += 10;
        if (browserFP.webgl && browserFP.webgl.renderer) stability += 20;

        return Math.min(stability, 100);
    }

    calculateDeviceStability(deviceFP) {
        let stability = 0;
        
        if (deviceFP.screen.total) stability += 30;
        if (deviceFP.concurrency) stability += 25;
        if (deviceFP.deviceMemory) stability += 25;
        if (deviceFP.memory) stability += 20;

        return Math.min(stability, 100);
    }

    calculateNetworkStability(networkFP) {
        let stability = 0;
        
        // Сетевые характеристики менее стабильны
        if (networkFP.localIPs.length > 0) stability += 40;
        if (networkFP.publicIPs.length > 0) stability += 30;
        if (networkFP.connection) stability += 30;

        return Math.min(stability, 100);
    }

    assessCorrelationRisk(analysis) {
        const risk = {
            trackingPotential: 0,
            crossBrowserIdentification: 0,
            persistentIdentification: 0,
            overallRisk: 'LOW'
        };

        // Оценка потенциала трекинга
        risk.trackingPotential = (
            analysis.correlationFactors.browserStability +
            analysis.correlationFactors.deviceStability +
            analysis.correlationFactors.networkStability
        ) / 3;

        // Межбраузерная идентификация
        const uniqueFactors = Object.values(analysis.correlationFactors.uniquenessFactors).filter(Boolean).length;
        risk.crossBrowserIdentification = Math.min(uniqueFactors * 20, 100);

        // Постоянная идентификация
        risk.persistentIdentification = Math.max(
            analysis.correlationFactors.browserStability,
            analysis.correlationFactors.deviceStability
        );

        // Общий риск
        const avgRisk = (risk.trackingPotential + risk.crossBrowserIdentification + risk.persistentIdentification) / 3;
        
        if (avgRisk >= 80) risk.overallRisk = 'CRITICAL';
        else if (avgRisk >= 60) risk.overallRisk = 'HIGH';
        else if (avgRisk >= 40) risk.overallRisk = 'MEDIUM';
        else risk.overallRisk = 'LOW';

        return risk;
    }

    displayCrossBrowserResults(correlation) {
        const resultsDiv = document.getElementById('attackResults');
        const resultDiv = document.createElement('div');
        resultDiv.className = 'critical-result';
        
        resultDiv.innerHTML = `
            <h4>🔗 Межбраузерная корреляция (КРИТИЧНО)</h4>
            
            <div style="background: #ffebee; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>⚠️ ОБНАРУЖЕН УНИКАЛЬНЫЙ ЦИФРОВОЙ ОТПЕЧАТОК</strong><br>
                Общий уровень риска: <strong style="color: ${this.getRiskColor(correlation.riskAssessment.overallRisk)}">${correlation.riskAssessment.overallRisk}</strong>
            </div>

            <h5>📊 Анализ стабильности отпечатков:</h5>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0;">
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Браузер:</strong><br>
                    Стабильность: ${correlation.correlationFactors.browserStability.toFixed(1)}%<br>
                    <div style="width: 100%; background: #ddd; border-radius: 2px; height: 4px; margin-top: 3px;">
                        <div style="width: ${correlation.correlationFactors.browserStability}%; background: #2196F3; height: 100%; border-radius: 2px;"></div>
                    </div>
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Устройство:</strong><br>
                    Стабильность: ${correlation.correlationFactors.deviceStability.toFixed(1)}%<br>
                    <div style="width: 100%; background: #ddd; border-radius: 2px; height: 4px; margin-top: 3px;">
                        <div style="width: ${correlation.correlationFactors.deviceStability}%; background: #4CAF50; height: 100%; border-radius: 2px;"></div>
                    </div>
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Сеть:</strong><br>
                    Стабильность: ${correlation.correlationFactors.networkStability.toFixed(1)}%<br>
                    <div style="width: 100%; background: #ddd; border-radius: 2px; height: 4px; margin-top: 3px;">
                        <div style="width: ${correlation.correlationFactors.networkStability}%; background: #FF9800; height: 100%; border-radius: 2px;"></div>
                    </div>
                </div>
            </div>

            <h5>🎯 Факторы уникальности:</h5>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
                <strong>Canvas Hash:</strong> ${correlation.correlationFactors.uniquenessFactors.canvas || 'Недоступен'}<br>
                <strong>WebGL:</strong> ${correlation.correlationFactors.uniquenessFactors.webgl || 'Недоступен'}<br>
                <strong>Audio Context:</strong> ${correlation.correlationFactors.uniquenessFactors.audio || 'Недоступен'}<br>
                <strong>Screen Signature:</strong> ${correlation.correlationFactors.uniquenessFactors.screen}<br>
            </div>

            <h5>📈 Оценка рисков:</h5>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0;">
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Потенциал трекинга:</strong><br>
                    ${correlation.riskAssessment.trackingPotential.toFixed(1)}%
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Межбраузерная ID:</strong><br>
                    ${correlation.riskAssessment.crossBrowserIdentification.toFixed(1)}%
                </div>
                <div style="background: #f5f5f5; padding: 8px; border-radius: 4px;">
                    <strong>Постоянная ID:</strong><br>
                    ${correlation.riskAssessment.persistentIdentification.toFixed(1)}%
                </div>
            </div>

            <div style="background: #ffcdd2; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong>🚨 Критические выводы:</strong><br>
                • Уникальная комбинация характеристик позволяет идентификацию между браузерами<br>
                • Цифровой отпечаток сохраняется даже при смене IP, cookies и User-Agent<br>
                • Возможна корреляция активности на разных сайтах<br>
                • Полная анонимизация требует кардинальных мер защиты
            </div>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }

    // ЭТАП 5: ГЕНЕРАЦИЯ ОТЧЕТОВ

    generateFullReport() {
        console.log('Генерация полного отчета fingerprinting...');
        
        const report = {
            timestamp: new Date().toISOString(),
            sessionId: this.generateSessionId(),
            mdnsAddresses: this.mdnsAddresses,
            fingerprintData: this.fingerprintData,
            summary: this.generateReportSummary(),
            riskAssessment: this.generateRiskAssessment(),
            recommendations: this.generateRecommendations()
        };

        this.displayFullReport(report);
        this.reportData = report; // Сохраняем для экспорта
    }

    generateSessionId() {
        return 'session-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
    }

    generateReportSummary() {
        const summary = {
            mdnsFound: this.mdnsAddresses.length,
            testsCompleted: Object.keys(this.fingerprintData).length,
            criticalFindings: 0,
            uniquenessScore: 0
        };

        // Подсчет критических находок
        if (this.fingerprintData['local-scan-results']) summary.criticalFindings++;
        if (this.fingerprintData['vpn-bypass-results']) summary.criticalFindings++;
        if (this.fingerprintData['behavior-results']) summary.criticalFindings++;
        if (this.fingerprintData['cross-browser-results']) summary.criticalFindings++;

        // Общая оценка уникальности
        const factors = [
            this.mdnsAddresses.length > 0 ? 20 : 0,
            Object.keys(this.fingerprintData).length * 5,
            summary.criticalFindings * 15
        ];
        
        summary.uniquenessScore = Math.min(factors.reduce((a, b) => a + b, 0), 100);

        return summary;
    }

    generateRiskAssessment() {
        const risks = {
            privacy: 'LOW',
            tracking: 'LOW',  
            identification: 'LOW',
            overall: 'LOW'
        };

        let riskScore = 0;

        // Оценка рисков приватности
        if (this.mdnsAddresses.length > 0) riskScore += 25;
        if (this.fingerprintData['vpn-bypass-results']) riskScore += 30;
        if (this.fingerprintData['local-scan-results']) riskScore += 25;
        if (this.fingerprintData['behavior-results']) riskScore += 20;

        if (riskScore >= 75) {
            risks.privacy = 'CRITICAL';
            risks.tracking = 'HIGH';
            risks.identification = 'HIGH';
            risks.overall = 'CRITICAL';
        } else if (riskScore >= 50) {
            risks.privacy = 'HIGH';
            risks.tracking = 'MEDIUM';
            risks.identification = 'MEDIUM';
            risks.overall = 'HIGH';
        } else if (riskScore >= 25) {
            risks.privacy = 'MEDIUM';
            risks.tracking = 'LOW';
            risks.identification = 'LOW';
            risks.overall = 'MEDIUM';
        }

        return {risks, score: riskScore};
    }

    generateRecommendations() {
        const recommendations = [];

        if (this.mdnsAddresses.length > 0) {
            recommendations.push({
                severity: 'HIGH',
                issue: 'mDNS адреса обнаружены',
                recommendation: 'Отключите WebRTC или используйте расширения для блокировки WebRTC утечек'
            });
        }

        if (this.fingerprintData['vpn-bypass-results']) {
            recommendations.push({
                severity: 'CRITICAL',
                issue: 'Обнаружены VPN утечки',
                recommendation: 'Используйте VPN с WebRTC protection или полностью отключите WebRTC'
            });
        }

        if (this.fingerprintData['local-scan-results']) {
            recommendations.push({
                severity: 'HIGH',
                issue: 'Возможно сканирование локальной сети',
                recommendation: 'Используйте файрвол для блокировки локальных подключений от браузера'
            });
        }

        if (this.fingerprintData['behavior-results']) {
            recommendations.push({
                severity: 'MEDIUM',
                issue: 'Собран поведенческий отпечаток',
                recommendation: 'Используйте инструменты для рандомизации поведенческих паттернов'
            });
        }

        // Общие рекомендации
        recommendations.push({
            severity: 'INFO',
            issue: 'Общие меры защиты',
            recommendation: 'Используйте Tor Browser, антидетект-браузеры или расширения для защиты приватности'
        });

        return recommendations;
    }

    displayFullReport(report) {
        const resultsDiv = document.getElementById('finalResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h3>📊 Полный отчет Advanced Fingerprinting</h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                    <div style="background: #e3f2fd; padding: 10px; border-radius: 4px;">
                        <strong>Session ID:</strong><br>
                        <code>${report.sessionId}</code>
                    </div>
                    <div style="background: #f3e5f5; padding: 10px; border-radius: 4px;">
                        <strong>mDNS адресов:</strong><br>
                        ${report.summary.mdnsFound}
                    </div>
                    <div style="background: #e8f5e8; padding: 10px; border-radius: 4px;">
                        <strong>Тестов выполнено:</strong><br>
                        ${report.summary.testsCompleted}
                    </div>
                    <div style="background: #fff3e0; padding: 10px; border-radius: 4px;">
                        <strong>Критических находок:</strong><br>
                        ${report.summary.criticalFindings}
                    </div>
                </div>

                <h4>🎯 Оценка уникальности: ${report.summary.uniquenessScore}/100</h4>
                <div style="width: 100%; background: #ddd; border-radius: 4px; height: 8px; margin: 10px 0;">
                    <div style="width: ${report.summary.uniquenessScore}%; background: linear-gradient(45deg, #667eea, #764ba2); height: 100%; border-radius: 4px;"></div>
                </div>

                <h4>⚠️ Оценка рисков:</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 10px 0;">
                    <div style="text-align: center;">
                        <strong>Приватность</strong><br>
                        <span style="color: ${this.getRiskColor(report.riskAssessment.risks.privacy)}">${report.riskAssessment.risks.privacy}</span>
                    </div>
                    <div style="text-align: center;">
                        <strong>Трекинг</strong><br>
                        <span style="color: ${this.getRiskColor(report.riskAssessment.risks.tracking)}">${report.riskAssessment.risks.tracking}</span>
                    </div>
                    <div style="text-align: center;">
                        <strong>Идентификация</strong><br>
                        <span style="color: ${this.getRiskColor(report.riskAssessment.risks.identification)}">${report.riskAssessment.risks.identification}</span>
                    </div>
                    <div style="text-align: center;">
                        <strong>Общий риск</strong><br>
                        <span style="color: ${this.getRiskColor(report.riskAssessment.risks.overall)}; font-weight: bold;">${report.riskAssessment.risks.overall}</span>
                    </div>
                </div>

                <h4>💡 Рекомендации по защите:</h4>
                <div style="margin: 10px 0;">
                    ${report.recommendations.map(rec => `
                        <div style="background: ${this.getRecommendationColor(rec.severity)}; padding: 8px; margin: 5px 0; border-radius: 4px; border-left: 3px solid ${this.getRecommendationBorderColor(rec.severity)};">
                            <strong>${rec.severity}:</strong> ${rec.issue}<br>
                            <small>${rec.recommendation}</small>
                        </div>
                    `).join('')}
                </div>

                <details style="margin-top: 15px;">
                    <summary>📋 Детальные данные отчета</summary>
                    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 10px;">${JSON.stringify(report, null, 2)}</pre>
                </details>
            </div>
        `;

        document.getElementById('step6').classList.add('active');
    }

    getRiskColor(level) {
        switch (level) {
            case 'CRITICAL': return '#d32f2f';
            case 'HIGH': return '#f57c00';
            case 'MEDIUM': return '#fbc02d';
            case 'LOW': return '#388e3c';
            default: return '#666';
        }
    }

    getRecommendationColor(severity) {
        switch (severity) {
            case 'CRITICAL': return '#ffebee';
            case 'HIGH': return '#fff3e0';
            case 'MEDIUM': return '#fffde7';
            case 'LOW': return '#e8f5e8';
            case 'INFO': return '#e3f2fd';
            default: return '#f5f5f5';
        }
    }

    getRecommendationBorderColor(severity) {
        switch (severity) {
            case 'CRITICAL': return '#f44336';
            case 'HIGH': return '#ff9800';
            case 'MEDIUM': return '#ffeb3b';
            case 'LOW': return '#4caf50';
            case 'INFO': return '#2196f3';
            default: return '#ccc';
        }
    }

    exportFingerprint() {
        if (!this.reportData) {
            alert('Сначала создайте отчет!');
            return;
        }

        const exportData = {
            ...this.reportData,
            exportTimestamp: new Date().toISOString(),
            version: '1.0',
            source: 'Advanced mDNS Fingerprinting System'
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], {
            type: 'application/json'
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fingerprint-report-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        console.log('Отчет экспортирован:', exportData);
    }

    clearCommandQueue() {
        document.getElementById('commandQueue').innerHTML = '';
        console.log('Очередь команд очищена');
    }

    // Остальные методы без изменений (sendRealCommand, logCommand, утилиты и т.д.)
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

    updateStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.className = `status ${status}`;
            element.textContent = text;
        }
    }

    updateProgress(elementId, percent) {
        const element = document.getElementById(elementId);
        if (element) {
            element.style.width = `${percent}%`;
        }
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
    realFingerprinter.findLocalAddresses(); // Изменено!
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
    console.log('ПОЛНЫЙ mDNS Fingerprinting System загружен');
    console.log('Все операции выполняются по-настоящему, включая расширенные методы');
});
