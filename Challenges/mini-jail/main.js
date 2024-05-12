const readline = require('node:readline');
const { isStringObject } = require('node:util/types');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

ohmylog_faeknvkaenfckajnvkdasngksnfkjaefnkajnefkajnckjenfiqeahfchneisugvnmfkaefnuidwkanfcaenfkwnjkfkwjnfmekafmlekmfmfaea = console.log;
ohmyeval_aaafseinfiwegnveuangviwenuqwertyujhgbfvdcxsvbnmkjyhtgrfdergthyjukmnbvfgdcvbnmfeanfnweaiodhowidnoancjazxcnofjepa = eval;
console = {
  log: (text) => {
    ohmylog_faeknvkaenfckajnvkdasngksnfkjaefnkajnefkajnckjenfiqeahfchneisugvnmfkaefnuidwkanfcaenfkwnjkfkwjnfmekafmlekmfmfaea({
      "msg": "No logs for you! I will only tell you the length of the input.",
      "inputLength": isStringObject(text) ? text.hasOwnProperty("length") ? text.length : "idk" : "not string"
    });
  }
};
eval = void 0;
File = void 0;
process = void 0;

rl.question('/* hint: if (answer.length > 120 || ... */\nGive me your payload\n', (answer) => {
  rl.close();
  // ohmylog_faeknvkaenfckajnvkdasngksnfkjaefnkajnefkajnckjenfiqeahfchneisugvnmfkaefnuidwkanfcaenfkwnjkfkwjnfmekafmlekmfmfaea(answer);
  if (answer.length > 120 || answer.match(/flag|write|read|fs|proc/ig)) {
    ohmylog_faeknvkaenfckajnvkdasngksnfkjaefnkajnefkajnckjenfiqeahfchneisugvnmfkaefnuidwkanfcaenfkwnjkfkwjnfmekafmlekmfmfaea("No flag for you!".toString());
    return;
  }
  result = ohmyeval_aaafseinfiwegnveuangviwenuqwertyujhgbfvdcxsvbnmkjyhtgrfdergthyjukmnbvfgdcvbnmfeanfnweaiodhowidnoancjazxcnofjepa(answer);
  // ohmylog_faeknvkaenfckajnvkdasngksnfkjaefnkajnefkajnckjenfiqeahfchneisugvnmfkaefnuidwkanfcaenfkwnjkfkwjnfmekafmlekmfmfaea(result);
});

