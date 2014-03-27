/**
 * NodeJS listener app
 * @author Alex <dtk077@gmail.com>
 */
var opts, mqtt, client, Memcached, existingUsers = [];

opts = {};
mqtt = require('mqtt');
var start;
mqttClientListener = mqtt.createClient(2000, '192.168.56.144', opts);
// mqttClientSender = mqtt.createClient(2000, 'btc1', opts);
Memcached=require('memcached');
memcachedClient = new Memcached({ 'localhost:11211': 1 }, {keyCompression: true});

mqttClientListener.subscribe('/hello', {qos: 2}, function (err, granted) {
console.log(err);
console.log(granted);
}).on('message', function (topic, msg) {
	console.log(msg);
	if (msg == '100000 - Bang!'){
		console.log('Started: '+start);
		console.log('Ended: '+ new Date());
	}
})
for (var i=1; i<=100000;i++){
	if (i==1){
		start=new Date();
	}
	mqttClientListener.publish('/hello',i+' - Bang!');
}