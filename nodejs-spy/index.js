/**
 * NodeJS listener app
 * @author Alex <dtk077@gmail.com>
 */

var opts, mqtt, client, Memcached, existingUsers = [];

opts = {};
mqtt = require('mqtt');
Memcached = require('memcached');
memcachedClient = new Memcached({ 'localhost:11211': 1 }, {keyCompression: true});
mqttClient = mqtt.createClient(2000, '85.25.242.185', opts);

mqttClient.subscribe('/#', {qos: 2}, function (err, granted) {
    console.log(granted);
    if (err != 'null') {
        if (granted) {
            memcachedClient.get('btcsms_users_mphone_numbers', function (err, res) {
                if (err != 'null' || err != 'undefined') {
                    if (res) {
                        res = JSON.parse(res);
                        res.forEach(function (phone) {
                            //console.log(phone);
                            mqttClient.publish('/user/' + phone, phone, {qos: 2, retain: true});
                        });
                    } else {
                        console.log('memcached client, nothing resolved: ' + res);
                    }
                } else {
                    console.log('memcached client, error: ' + err);
                }
                //console.log('something else, err: ' + err + ' res: ' + res);
            });
        } else {
            console.log('mqtt client, nothing resolved: ' + granted);
        }
    } else {
        console.log('mqtt client, error: ' + err);
    }
}).on('message', function (topic, msg) {

    console.log(msg);
    console.log(topic);

    /*msg = JSON.parse(msg);
    memcachedClient.set('btcsms_'+msg.phone, msg, 0, function (err, result) {
        if (err)
            console.error(err);

        console.dir(result);
    });
    memcachedClient.get('btcsms_'+msg.phone, function (err, res) {
        console.log(res);
    });*/
});