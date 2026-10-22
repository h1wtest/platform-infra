const http = require('http');

async function main() {
  const targetUrl = process.env.BENCHMARK_URL || 'http://localhost:80/.well-known/openid-configuration';
  const totalRequests = parseInt(process.env.TOTAL_REQUESTS || '500', 10);
  const concurrency = parseInt(process.env.CONCURRENCY || '25', 10);

  console.log('===========================================================');
  console.log('       SSO PLATFORM: AUTOMATED LOAD BENCHMARK              ');
  console.log('===========================================================');
  console.log(`Целевой URL:    ${targetUrl}`);
  console.log(`Всего запросов: ${totalRequests}`);
  console.log(`Конкурентность: ${concurrency} воркеров`);
  console.log('-----------------------------------------------------------');

  let completed = 0;
  let success200 = 0;
  let failed = 0;
  const start = Date.now();

  async function worker() {
    while (completed < totalRequests) {
      completed++;
      try {
        const res = await fetch(targetUrl);
        if (res.status === 200) {
          success200++;
        } else {
          failed++;
        }
      } catch (err) {
        failed++;
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  const durationMs = Date.now() - start;
  const rps = ((totalRequests / durationMs) * 1000).toFixed(2);
  const successRate = ((success200 / totalRequests) * 100).toFixed(2);

  console.log('РЕЗУЛЬТАТЫ:');
  console.log(`  Успешно (200 OK):  ${success200} / ${totalRequests}`);
  console.log(`  Ошибок:            ${failed}`);
  console.log(`  Время выполнения:  ${durationMs} ms`);
  console.log(`  RPS (запросов/сек): ${rps}`);
  console.log(`  Процент успеха:    ${successRate}%`);
  console.log('-----------------------------------------------------------');

  if (failed > 0 || success200 < totalRequests) {
    console.error('❌ БЕНЧМАРК ПРОВАЛЕН: обнаружены ошибки при нагрузке.');
    process.exit(1);
  } else {
    console.log('✅ БЕНЧМАРК ПРОЙДЕН УСПЕШНО (100% 200 OK).');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Критическая ошибка бенчмарка:', err);
  process.exit(1);
});
