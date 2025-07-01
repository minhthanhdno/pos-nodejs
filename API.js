const request = require("request");
const { Expo } = require('expo-server-sdk');
const { server } = require("./configs.json");

function getDataFromSTPService(url) {
  const p = new Promise((resolve, reject) => {
    request(url, function (error, response, body) {
      if (error) return reject(error);
      if (body.indexOf("ERROR") >= 0) {
        return reject(body);
      }
      try {
        body = JSON.parse(body);
        resolve(body)
      } catch (e) {
        reject(e.message);
      }
    });
  })
  return p;
}



async function getEndpoint(database, email, token) {
  let id_rpt = 'get_endpoint';
  let stt = '1';
  let url = server + database + "/report/" + id_rpt + "/" + stt + "?token=" + token;
  return await getDataFromSTPService(url)
}

async function emitEvent(email, event, _data, push, database, token, endpoint) {
  let data;
  if (typeof (_data) === "object") {
    data = Object.assign({}, _data);
    data.__event = event;
  } else {
    data = _data;
  }
  //web push, expo push
  if ((data.title || data.body) && (push || push === undefined)) {
    //web push
    if (data.title) data.title = data.title.replace(/<[^>]*>?/gm, '');
    if (data.body) data.body = data.body.replace(/<[^>]*>?/gm, '');
    const expo = new Expo();
    const messages = [];
    if (endpoint) {
      if (Expo.isExpoPushToken(endpoint)) {
        messages.push({
          to: endpoint,
          sound: 'default',
          badge: 1,
          title: data.title,
          body: (data.body !== data.title ? data.body : ""),
          data: data,
          channelId: data.channel || "default"
        })
      }
    } else {
      const eps = await getEndpoint(database, email, token);
      eps.forEach(ep => {
        //check ep
        if (Expo.isExpoPushToken(ep.endpoint)) {
          messages.push({
            to: ep.endpoint,
            sound: 'default',
            badge: 1,
            title: data.title,
            body: (data.body !== data.title ? data.body : ""),
            data: data,
            channelId: data.channel || "default"
          })
        }
      })
    }
    //expo push notification to apple and google
    messages.forEach(message => {
      let chunks = expo.chunkPushNotifications([message]);
      let tickets = [];
      (async () => {
        for (let chunk of chunks) {
          try {
            console.log("mobile push", email, event)
            let ticketChunk = await expo.sendPushNotificationsAsync(chunk);
            tickets.push(...ticketChunk);
          } catch (error) {
            console.error(error);
          }
        }
      })();
    })
  }
}
module.exports = {
  getDataFromSTPService, emitEvent
}
