const { exec } = require('child_process');

async function main() {
  const targetUrl = process.env.CHAOS_URL || 'http://localhost:80/.well-known/openid-configuration';
  const durationSec = parseInt(process.env.CHAOS_DURATION_SEC || '8', 10);
  const concurrency = parseInt(process.env.CHAOS_CONCURRENCY || '20', 10);
  const isK8s = process.env.CHAOS_K8S === 'true' || targetUrl.includes(':8088');
  const targetContainer = process.env.KILL_TARGET || (isK8s ? 'k8s-identity-pod' : 'sso_platform-identity-service-1');

  console.log('===========================================================');
  console.log('       SSO PLATFORM: AUTOMATED CHAOS FAILURE TEST          ');
  console.log('===========================================================');
  console.log(`Целевой URL:        ${targetUrl}`);
  console.log(`Длительность теста: ${durationSec} секунд`);
  console.log(`Конкурентность:     ${concurrency} параллельных потоков`);
  console.log(`Цель для убийства:  ${targetContainer}`);
  console.log('-----------------------------------------------------------');

  const start = Date.now();
  let total = 0;
  let success200 = 0;
  let failed = 0;
  let killed = false;

  async function worker() {
    while (Date.now() - start < durationSec * 1000) {
      total++;
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
      await new Promise(r => setTimeout(r, 15));
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());

  // Trigger chaos kill at 35% of total time
  setTimeout(() => {
    if (isK8s) {
      console.log(`\n💥 [CHAOS TRIGGER] Принудительно убиваем случайный под identity-service в Kubernetes...`);
      exec("kubectl get pods -n sso-platform -l app=identity-service -o jsonpath='{.items[0].metadata.name}'", (err, stdout) => {
        const podName = stdout.trim();
        if (podName) {
          exec(`kubectl delete pod -n sso-platform ${podName} --wait=false`, (err2) => {
            if (!err2) {
              console.log(`   Убит под Kubernetes: ${podName}`);
              killed = true;
            } else {
              console.warn(`   Не удалось удалить под: ${err2.message}`);
            }
          });
        }
      });
    } else {
      console.log(`\n💥 [CHAOS TRIGGER] Принудительно убиваем контейнер ${targetContainer}...`);
      exec(`docker kill ${targetContainer}`, (err, stdout) => {
        if (err) {
          console.warn(`   Не удалось выполнить docker kill: ${err.message}`);
        } else {
          console.log(`   Убит узел: ${stdout.trim()}`);
          killed = true;
        }
      });
    }
  }, Math.floor(durationSec * 350));

  await Promise.all(workers);

  const successRate = total > 0 ? ((success200 / total) * 100).toFixed(2) : 0;

  console.log('\nРЕЗУЛЬТАТЫ СТРЕСС-ТЕСТА НА ОТКАЗ:');
  console.log(`  Всего отправлено запросов:   ${total}`);
  console.log(`  Успешно (200 OK):            ${success200}`);
  console.log(`  Ошибок (502 / Connection):   ${failed}`);
  console.log(`  Процент доступности:         ${successRate}%`);
  console.log('-----------------------------------------------------------');

  if (isK8s) {
    console.log('Kubernetes Controller автоматически восстанавливает реплики подов.');
    if (failed > 0 || success200 === 0) {
      console.error('❌ CHAOS ТЕСТ ПРОВАЛЕН: зафиксированы ошибки при отказе узла.');
      process.exit(1);
    } else {
      console.log('✅ CHAOS ТЕСТ ПРОЙДЕН УСПЕШНО: нулевой даунтайм при смерти инстанса (100% 200 OK).');
      process.exit(0);
    }
  } else {
    console.log('Восстановление кластера после теста...');
    exec('docker compose up -d --scale identity-service=3 --scale user-notification-service=3', (err) => {
      if (err) {
        console.warn('Предупреждение при восстановлении:', err.message);
      } else {
        console.log('Кластер восстановлен до 3 реплик.');
      }
      if (failed > 0 || success200 === 0) {
        console.error('❌ CHAOS ТЕСТ ПРОВАЛЕН: зафиксированы ошибки при отказе узла.');
        process.exit(1);
      } else {
        console.log('✅ CHAOS ТЕСТ ПРОЙДЕН УСПЕШНО: нулевой даунтайм при смерти инстанса (100% 200 OK).');
        process.exit(0);
      }
    });
  }
}

main().catch(err => {
  console.error('Критическая ошибка chaos-теста:', err);
  process.exit(1);
});
