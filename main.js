const axios = require('axios');
const { ethers } = require('ethers');
const crypto = require('crypto');
const UserAgent = require('user-agents');
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});
const fs = require('fs').promises;

const { HttpsProxyAgent } = require('https-proxy-agent');
const http = require('http');
const https = require('https');

const isProxyAlive = async (proxyLine) => {
  try {
    const [ip, port, user, pass] = proxyLine.split(':');
    const proxyUrl = `http://${user}:${pass}@${ip}:${port}`;
    const agent = new HttpsProxyAgent(proxyUrl);

    await axios.get('https://api.ipify.org?format=json', {
      httpsAgent: agent,
      timeout: 5000,
    });
    return true;
  } catch (err) {
    console.error(`Proxy lỗi: ${proxyLine} - ${err.message}`);
    return false;
  }
};

const createAxiosInstance = (proxyInfo, userAgent) => {
  const headers = {
    ...baseHeaders,
    'User-Agent': userAgent,
  };

  let httpsAgent = null;

  if (proxyInfo && proxyInfo.alive) {
    const [ip, port, user, pass] = proxyInfo.info.split(':');
    const proxyUrl = `http://${user}:${pass}@${ip}:${port}`;
    httpsAgent = new HttpsProxyAgent(proxyUrl);
  }

  return axios.create({
    headers,
    httpsAgent,
    proxy: false,
    timeout: 10000,
  });
};

const colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  white: '\x1b[37m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  wallet: (msg) => console.log(`${colors.yellow}[➤] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log('-------------------------');
    console.log('     KiteAI Auto Bot     ');
    console.log(`-------------------------${colors.reset}\n`);
  },
  agent: (msg) => console.log(`${colors.white}${msg}${colors.reset}`)
};

const agents = [
  { name: 'Professor', service_id: 'deployment_KiMLvUiTydioiHm7PWZ12zJU' },
  { name: 'Crypto Buddy', service_id: 'deployment_ByVHjMD6eDb9AdekRIbyuz14' },
  { name: 'Sherlock', service_id: 'deployment_OX7sn2D0WvxGUGK8CTqsU5VJ' }
];

const loadPrompts = async () => {
  try {
    const content = await fs.readFile('prompt.txt', 'utf8');
    const lines = content.split('\n').map(line => line.trim());
    const promptGenerators = {};
    let currentAgent = null;

    for (const line of lines) {
      if (line.startsWith('[') && line.endsWith(']')) {
        currentAgent = line.slice(1, -1).trim();
        promptGenerators[currentAgent] = [];
      } else if (line && !line.startsWith('#') && currentAgent) {
        promptGenerators[currentAgent].push(line);
      }
    }

    for (const agent of agents) {
      if (!promptGenerators[agent.name] || promptGenerators[agent.name].length === 0) {
        logger.error(`No prompts found for agent ${agent.name} in prompt.txt`);
        process.exit(1);
      }
    }

    return promptGenerators;
  } catch (error) {
    logger.error(`Failed to load prompt.txt: ${error.message}`);
    process.exit(1);
  }
};

const getRandomPrompt = (agentName, promptGenerators) => {
  const prompts = promptGenerators[agentName] || [];
  return prompts[Math.floor(Math.random() * prompts.length)];
};

const userAgent = new UserAgent();
const baseHeaders = {
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
  'Origin': 'https://testnet.gokite.ai',
  'Referer': 'https://testnet.gokite.ai/',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-site',
  'User-Agent': userAgent.toString(),
  'Content-Type': 'application/json'
};

const KITE_AI_SUBNET = '0xb132001567650917d6bd695d1fab55db7986e9a5';

const getWallet = (privateKey) => {
  try {
    const wallet = new ethers.Wallet(privateKey);
    logger.info(`Wallet created: ${wallet.address}`);
    return wallet;
  } catch (error) {
    logger.error(`Sai định dạng private key: ${error.message}`);
    return null;
  }
};

const encryptAddress = (address) => {
  try {
    const keyHex = '6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a';
    const key = Buffer.from(keyHex, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(address, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const result = Buffer.concat([iv, encrypted, authTag]);
    return result.toString('hex');
  } catch (error) {
    logger.error(`Auth token generation failed for ${address}`);
    return null;
  }
};

const extractCookies = (headers) => {
  try {
    const rawCookies = headers['set-cookie'] || [];
    const skipKeys = ['expires', 'path', 'domain', 'samesite', 'secure', 'httponly', 'max-age'];
    const cookiesDict = {};
    
    for (const cookieStr of rawCookies) {
      const parts = cookieStr.split(';');
      for (const part of parts) {
        const cookie = part.trim();
        if (cookie.includes('=')) {
          const [name, value] = cookie.split('=', 2);
          if (name && value && !skipKeys.includes(name.toLowerCase())) {
            cookiesDict[name] = value;
          }
        }
      }
    }
    
    return Object.entries(cookiesDict).map(([key, value]) => `${key}=${value}`).join('; ') || null;
  } catch (error) {
    return null;
  }
};

const solveRecaptcha = async (url, apiKey, maxRetries = 3) => {
  const siteKey = '6Lc_VwgrAAAAALtx_UtYQnW-cFg8EPDgJ8QVqkaz';
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.loading(`Solving reCAPTCHA with 2Captcha (Attempt ${attempt}/${maxRetries})`);
      
      const requestUrl = `http://2captcha.com/in.php?key=${apiKey}&method=userrecaptcha&googlekey=${siteKey}&pageurl=${url}&json=1`;
      const requestResponse = await axios.get(requestUrl);
      
      if (requestResponse.data.status !== 1) {
        logger.error(`Failed to submit reCAPTCHA task: ${requestResponse.data.error_text}`);
        if (attempt === maxRetries) return null;
        await new Promise(resolve => setTimeout(resolve, 5000));
        continue;
      }
      
      const requestId = requestResponse.data.request;
      logger.step(`reCAPTCHA task submitted, ID: ${requestId}`);
      
      let pollAttempts = 0;
      const maxPollAttempts = 30;
      const pollInterval = 5000;
      
      while (pollAttempts < maxPollAttempts) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        const resultUrl = `http://2captcha.com/res.php?key=${apiKey}&action=get&id=${requestId}&json=1`;
        const resultResponse = await axios.get(resultUrl);
        
        if (resultResponse.data.status === 1) {
          logger.success('reCAPTCHA solved successfully');
          return resultResponse.data.request;
        }
        
        if (resultResponse.data.request === 'ERROR_CAPTCHA_UNSOLVABLE') {
          logger.error('reCAPTCHA unsolvable');
          if (attempt === maxRetries) return null;
          break;
        }
        
        pollAttempts++;
        logger.step(`Waiting for reCAPTCHA solution (Attempt ${pollAttempts}/${maxPollAttempts})`);
      }
    } catch (error) {
      logger.error(`reCAPTCHA solving error: ${error.message}`);
      if (attempt === maxRetries) return null;
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
  
  logger.error('reCAPTCHA solving failed after maximum retries');
  return null;
};

const claimDailyFaucet = async (access_token, cookieHeader, apiKey, axiosInstance) => {
  try {
    logger.loading('Đang thực hiện claim faucet daily...');
    
    const pageUrl = 'https://testnet.gokite.ai';
    const recaptchaToken = await solveRecaptcha(pageUrl, apiKey);
    
    if (!recaptchaToken) {
      logger.error('Lỗi sử dụng reCAPTCHA token');
      return false;
    }
    
    const faucetHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`,
      'x-recaptcha-token': recaptchaToken
    };
    
    if (cookieHeader) {
      faucetHeaders['Cookie'] = cookieHeader;
    }
    
    const response = await axiosInstance.post('https://ozone-point-system.prod.gokite.ai/blockchain/faucet-transfer', {}, {
      headers: faucetHeaders
    });
    
    if (response.data.error) {
      logger.error(`Faucet claim failed: ${response.data.error}`);
      return false;
    }
    
    logger.success('Claim faucet daily thành công');
    return true;
  } catch (error) {
    logger.error(`Faucet claim error: ${error.response?.data?.error || error.message}`);
    return false;
  }
};

const getStakeInfo = async (access_token, cookieHeader, axiosInstance) => {
  try {
    logger.loading('Đang lấy thông tin Staker...');
    
    const stakeHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`
    };
    
    if (cookieHeader) {
      stakeHeaders['Cookie'] = cookieHeader;
    }
    
    const response = await axiosInstance.get('https://ozone-point-system.prod.gokite.ai/subnet/3/staked-info?id=3', {
      headers: stakeHeaders
    });
    
    if (response.data.error) {
      logger.error(`Failed để lấy thông tin Staker: ${response.data.error}`);
      return null;
    }
    
    return response.data.data;
  } catch (error) {
    logger.error(`Stake info fetch error: ${error.response?.data?.error || error.message}`);
    return null;
  }
};

const stakeToken = async (access_token, cookieHeader, maxRetries = 5, axiosInstance) => {
  try {
    logger.loading('Đang stake 1 KITE token...');
    
    const stakeHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`
    };
    
    if (cookieHeader) {
      stakeHeaders['Cookie'] = cookieHeader;
    }
    
    const payload = {
      subnet_address: KITE_AI_SUBNET,
      amount: 1
    };
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const response = await axiosInstance.post('https://ozone-point-system.prod.gokite.ai/subnet/delegate', payload, {
          headers: stakeHeaders
        });
        
        if (response.data.error) {
          logger.error(`Stake failed: ${response.data.error}`);
          return false;
        }
        
        logger.success(`Successfully staked 1 KITE token`);
        return true;
      } catch (error) {
        if (attempt === maxRetries) {
          logger.error(`Stake error sau ${maxRetries} lần thử với lỗi: ${error.response?.data?.error || error.message}`);
          return false;
        }
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  } catch (error) {
    logger.error(`Stake error: ${error.response?.data?.error || error.message}`);
    return false;
  }
};

const claimStakeRewards = async (access_token, cookieHeader, maxRetries = 5, axiosInstance) => {
  try {
    logger.loading('Đang claim phần thưởng Stake...');
    
    const claimHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`
    };
    
    if (cookieHeader) {
      claimHeaders['Cookie'] = cookieHeader;
    }
    
    const payload = {
      subnet_address: KITE_AI_SUBNET
    };
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const response = await axiosInstance.post('https://ozone-point-system.prod.gokite.ai/subnet/claim-rewards', payload, {
          headers: claimHeaders
        });
        
        if (response.data.error) {
          logger.error(`Claim rewards failed: ${response.data.error}`);
          return false;
        }
        
        const reward = response.data.data?.claim_amount || 0;
        logger.success(`Thành công claim ${reward} KITE`);
        return true;
      } catch (error) {
        if (attempt === maxRetries) {
          logger.error(`Claim rewards error after ${maxRetries} attempts: ${error.response?.data?.error || error.message}`);
          return false;
        }
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  } catch (error) {
    logger.error(`Claim rewards error: ${error.response?.data?.error || error.message}`);
    return false;
  }
};

const login = async (wallet, neo_session = null, refresh_token = null, axiosInstance, maxRetries = 3) => {
  const url = 'https://neo.prod.gokite.ai/v2/signin';
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.loading(`Đang đăng nhập tới ví ${wallet.address} (Số lần thử: ${attempt}/${maxRetries})`);

      const authToken = encryptAddress(wallet.address);
      if (!authToken) return null;

      const loginHeaders = {
        ...baseHeaders,
        'Authorization': authToken,
      };

      if (neo_session || refresh_token) {
        const cookies = [];
        if (neo_session) cookies.push(`neo_session=${neo_session}`);
        if (refresh_token) cookies.push(`refresh_token=${refresh_token}`);
        loginHeaders['Cookie'] = cookies.join('; ');
      }

      const body = { eoa: wallet.address };

      const response = await axiosInstance.post(url, body, { headers: loginHeaders });

      if (response.data.error) {
        logger.error(`Login failed với ví ${wallet.address}: ${response.data.error}`);
        return null;
      }

      const { access_token, aa_address, displayed_name, avatar_url } = response.data.data;
      const cookieHeader = extractCookies(response.headers);

      let resolved_aa_address = aa_address;
      if (!resolved_aa_address) {
        const profile = await getUserProfile(access_token, axiosInstance);
        resolved_aa_address = profile?.profile?.smart_account_address;
        if (!resolved_aa_address) {
          logger.error(`Chưa có tài khoản Kite nào đăng ký với địa chỉ ví ${wallet.address}`);
          return null;
        }
      }

      logger.success(`Đăng nhập thành công cho ví ${wallet.address}`);
      return { access_token, aa_address: resolved_aa_address, displayed_name, avatar_url, cookieHeader };
    } catch (error) {
      const errorMessage = error.response?.data?.error || error.message;
      if (attempt === maxRetries) {
        logger.error(`Login failed cho ví ${wallet.address} sau ${maxRetries} lần thử với lỗi: ${errorMessage}`);
        return null;
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
};


const getUserProfile = async (access_token, axiosInstance) => {
  try {
    const response = await axiosInstance.get('https://ozone-point-system.prod.gokite.ai/me', {
      headers: { ...baseHeaders, Authorization: `Bearer ${access_token}` }
    });
    
    if (response.data.error) {
      logger.error(`Failed to fetch profile: ${response.data.error}`);
      return null;
    }
    
    return response.data.data;
  } catch (error) {
    logger.error(`Profile fetch error: ${error.message}`);
    return null;
  }
};

const receiptCache = new Map(); // Global cache để lưu các receipt ID theo agent+prompt

const interactWithAgent = async (access_token, aa_address, cookieHeader, agent, prompt, interactionCount, axiosInstance) => {
  if (!aa_address) {
    logger.error(`Cannot interact with ${agent.name}: No aa_address`);
    return null;
  }

  const cacheKey = `${agent.name}-${prompt}`;

  while (true) {
    try {
      logger.step(`Interaction ${interactionCount} - Prompts : ${prompt}`);

      let id = receiptCache.get(cacheKey);

      if (!id) {
        const inferenceHeaders = {
          ...baseHeaders,
          Authorization: `Bearer ${access_token}`,
          Accept: 'text/event-stream'
        };
        if (cookieHeader) {
          inferenceHeaders['Cookie'] = cookieHeader;
        }

        const inferenceResponse = await axiosInstance.post('https://ozone-point-system.prod.gokite.ai/agent/inference', {
          service_id: agent.service_id,
          subnet: 'kite_ai_labs',
          stream: true,
          body: { stream: true, message: prompt }
        }, {
          headers: inferenceHeaders,
          timeout: 60000
        });

        let output = '';
        const lines = inferenceResponse.data.split('\n');
        for (const line of lines) {
          if (line.startsWith('data: ') && line !== 'data: [DONE]') {
            try {
              const data = JSON.parse(line.replace('data: ', ''));
              if (data.choices && data.choices[0].delta.content) {
                output += data.choices[0].delta.content;
                if (output.length > 100) {
                  output = output.substring(0, 100) + '...';
                  break;
                }
              }
            } catch (e) {}
          }
        }

        // Delay 5 giây sau khi lấy output
        await new Promise(resolve => setTimeout(resolve, 5000));

        const receiptHeaders = {
          ...baseHeaders,
          Authorization: `Bearer ${access_token}`
        };
        if (cookieHeader) {
          receiptHeaders['Cookie'] = cookieHeader;
        }

        const receiptResponse = await axiosInstance.post('https://neo.prod.gokite.ai/v2/submit_receipt', {
          address: aa_address,
          service_id: agent.service_id,
          input: [{ type: 'text/plain', value: prompt }],
          output: [{ type: 'text/plain', value: output || 'No response' }]
        }, {
          headers: receiptHeaders,
          timeout: 60000
        });

        if (receiptResponse.data.error) {
          throw new Error(`Receipt submission failed: ${receiptResponse.data.error}`);
        }

        id = receiptResponse.data.data.id;
        logger.step(`Interaction ${interactionCount} - Receipt submitted, ID: ${id}`);
        receiptCache.set(cacheKey, id);
      }

      // Delay 5 giây sau khi submit receipt
      await new Promise(resolve => setTimeout(resolve, 5000));

      let statusResponse;
      let attempts = 0;
      const maxAttempts = 10;
      while (attempts < maxAttempts) {
        statusResponse = await axiosInstance.get(`https://neo.prod.gokite.ai/v1/inference?id=${id}`, {
          headers: { ...baseHeaders, Authorization: `Bearer ${access_token}` },
          timeout: 60000
        });

        if (statusResponse.data.data.processed_at && statusResponse.data.data.tx_hash) {
          logger.step(`Interaction ${interactionCount} - Inference processed, tx_hash : ${statusResponse.data.data.tx_hash}`);
          receiptCache.delete(cacheKey); // Xoá khỏi cache khi thành công
          return statusResponse.data.data;
        }

        attempts++;
        await new Promise(resolve => setTimeout(resolve, 15000)); // Delay 15s mỗi lần check
      }

      throw new Error(`Inference status not completed after ${maxAttempts} attempts`);

    } catch (error) {
      logger.error(`Error interacting with ${agent.name} (retrying...): ${error.response?.data?.error || error.message}`);
      await new Promise(resolve => setTimeout(resolve, 15000)); // Delay 15s trước khi retry vòng lặp
    }
  }
};

const getNextRunTime = () => {
  const now = new Date();
  now.setHours(now.getHours() + 24);
  now.setMinutes(0);
  now.setSeconds(0);
  now.setMilliseconds(0);
  return now;
};

const displayCountdown = (nextRunTime, interactionCount, apiKey) => {
  const updateCountdown = () => {
    const now = new Date();
    const timeLeft = nextRunTime - now;
    
    if (timeLeft <= 0) {
      logger.info('Đang bắt đầu auto Kite ngày mới...');
      clearInterval(countdownInterval);
      dailyRun(interactionCount, apiKey); 
      return;
    }

    const hours = Math.floor(timeLeft / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
    
    process.stdout.write(`\r${colors.cyan}[⏰] Lần chạy tiếp theo dự kiến: ${hours}h ${minutes}m ${seconds}s${colors.reset} `);
  };

  updateCountdown();
  const countdownInterval = setInterval(updateCountdown, 1000);
};

let interactionCount = null;
let apiKey = null;

const delayWithRandom = (baseDelay) => {
  const randomExtra = Math.floor(Math.random() * 41) + 40; // 40 - 80
  return new Promise(resolve => setTimeout(resolve, (baseDelay + randomExtra) * 1000));
};

const processWallet = async (index, privateKey, proxyList, userAgents, promptGenerators) => {
  const wallet = getWallet(privateKey);
  if (!wallet) return;

  const proxyInfo = proxyList[index % proxyList.length];
  const proxyAlive = await isProxyAlive(proxyInfo);
  const userAgent = userAgents[index % userAgents.length];
  const axiosInstance = createAxiosInstance(
    proxyAlive ? { info: proxyInfo, alive: true } : null,
    userAgent
  );

  logger.wallet(`Đang xử lý ví: ${wallet.address}`);
  if (proxyAlive) {
    const [ip, port] = proxyInfo.split(':');
    logger.info(`Sử dụng proxy: ${ip}:${port}`);
  } else {
    logger.info('Sử dụng IP local (proxy lỗi!!!)');
  }

  const loginData = await login(wallet, null, null, axiosInstance);
  if (!loginData) {
    logger.error(`[!] Đăng nhập không thành công cho ví: ${wallet.address}, bỏ qua...`);
    return;
  }

  const { access_token, aa_address, displayed_name, cookieHeader } = loginData;
  if (!aa_address) return;

  const profile = await getUserProfile(access_token, axiosInstance);
  if (!profile) return;

  logger.info(`User: ${profile.profile.displayed_name || displayed_name || 'Không rõ'}`);
  logger.info(`Địa chỉ EVM: ${profile.profile.eoa_address || wallet.address}`);
  logger.info(`Smart Account: ${profile.profile.smart_account_address || aa_address}`);
  logger.info(`Tổng điểm XP: ${profile.profile.total_xp_points || 0}`);
  logger.info(`Mã giới thiệu: ${profile.profile.referral_code || 0}`);
  logger.info(`Số huy hiệu đã mint: ${profile.profile.badges_minted?.length || 0}`);
  logger.info(`Twitter: ${profile.social_accounts?.twitter?.id ? 'Connected' : 'Chưa'}`);

  const stakeInfo = await getStakeInfo(access_token, cookieHeader, axiosInstance);
  if (stakeInfo) {
    logger.info(`----- Thông tin Staking -----`);
    logger.info(`Số token đã stake: ${stakeInfo.my_staked_amount}`);
    logger.info(`Tổng số token đã stake: ${stakeInfo.staked_amount}`);
    logger.info(`Số lượng người stake: ${stakeInfo.delegator_count}`);
    logger.info(`APR: ${stakeInfo.apr}%`);
    logger.info(`-----------------------------`);
  }

  if (apiKey) {
    await claimDailyFaucet(access_token, cookieHeader, apiKey, axiosInstance);
  } else {
    logger.info('Bỏ qua nhận faucet (không có API key 2Captcha)');
  }

  await stakeToken(access_token, cookieHeader, 5, axiosInstance);
  await claimStakeRewards(access_token, cookieHeader, 5, axiosInstance);

  for (const agent of agents) {
    logger.agent(`\n----- ${agent.name.toUpperCase()} -----`);
    for (let i = 0; i < interactionCount; i++) {
      const prompt = getRandomPrompt(agent.name, promptGenerators);
      await interactWithAgent(access_token, aa_address, cookieHeader, agent, prompt, i + 1, axiosInstance);
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
    logger.agent('\n');
  }
};

const dailyRun = async () => {
  logger.banner();

  const promptGenerators = await loadPrompts();

  const privateKeys = (await fs.readFile('privatekey.txt', 'utf8'))
    .split('\n').map(x => x.trim()).filter(Boolean);
  const proxyList = (await fs.readFile('proxy.txt', 'utf8'))
    .split('\n').map(x => x.trim()).filter(Boolean);
  const userAgents = (await fs.readFile('useragents.txt', 'utf8'))
    .split('\n').map(x => x.trim()).filter(Boolean);

  if (interactionCount === null) {
    interactionCount = await new Promise(resolve => {
      readline.question('Nhập số lần chat với mỗi agent bot: ', answer => {
        const count = parseInt(answer);
        if (isNaN(count) || count < 1 || count > 99999) {
          logger.error('Giá trị không hợp lệ. Vui lòng nhập số từ 1 đến 99999.');
          process.exit(1);
        }
        resolve(count);
      });
    });
  }

  if (apiKey === null) {
    apiKey = await new Promise(resolve => {
      readline.question('Nhập API key 2Captcha (Enter nếu muốn bỏ qua claim faucet): ', answer => {
        resolve(answer.trim() || null);
      });
    });
  }

  const batchSize = await new Promise(resolve => {
    readline.question('Nhập số lượng ví chạy song song (tối đa 5): ', answer => {
      const num = parseInt(answer);
      if (isNaN(num) || num < 1 || num > 5) {
        logger.error('Giá trị không hợp lệ. Phải là số từ 1 đến 5.');
        process.exit(1);
      }
      resolve(num);
    });
  });

  const baseDelay = await new Promise(resolve => {
    readline.question('Nhập time delay giữa các lô chạy (giây): ', answer => {
      const sec = parseInt(answer);
      if (isNaN(sec) || sec < 0 || sec > 3600) {
        logger.error('Giá trị không hợp lệ. Nhập số từ 0 đến 3600 giây.');
        process.exit(1);
      }
      resolve(sec);
    });
  });

  for (let i = 0; i < privateKeys.length; i += batchSize) {
    const batch = privateKeys.slice(i, i + batchSize);
    await Promise.all(batch.map((pk, idx) =>
      processWallet(i + idx, pk, proxyList, userAgents, promptGenerators)
    ));

    if (i + batchSize < privateKeys.length) {
      logger.info(`Đang đợi trước khi chạy lô tiếp theo...`);
      await delayWithRandom(baseDelay);
    }
  }

  logger.success('Hoàn tất quá trình chạy bot.');
  const nextRunTime = getNextRunTime();
  logger.info(`[⏰] Lần chạy tiếp theo dự kiến: ${nextRunTime.toLocaleString()}`);
  displayCountdown(nextRunTime, interactionCount, apiKey);
};

const main = async () => {
  try {
    await dailyRun(interactionCount, apiKey);
  } catch (error) {
    logger.error(`Lỗi bot: ${error.response?.data?.error || error.message}`);
    const nextRunTime = getNextRunTime();
    logger.info(`[⏰] Lần chạy tiếp theo dự kiến: ${nextRunTime.toLocaleString()}`);
    displayCountdown(nextRunTime, interactionCount, apiKey);
  }
};

main().catch(error => logger.error(`Lỗi nghiêm trọng: ${error.message}`));
