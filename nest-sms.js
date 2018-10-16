'use latest';
import bodyParser from 'body-parser';
import express from 'express';
import Webtask from 'webtask-tools';
import util from 'util';
import request from 'request';
import async from 'async';
import _ from 'lodash';
import qs from 'qs';
import ejs from 'ejs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cookieSession from 'cookie-session';
import { MongoClient } from 'mongodb';

const server = express();

server.use(bodyParser.json());
server.use(bodyParser.urlencoded({ extended: false }));
server.use(cookieParser());
server.use(cookieSession({
  name: 'session',
  keys: ['This is the session pasword - replace with your own']
}));

//A handler for all errors
server.use((e, req, res, next)=>{
  res.end(ejs.render(hereDoc(genericMsgForm), { msg: e }));
});

//This middleware simply maintans a `config` object. Uses another WT where secrets are kept.
var config;
server.use((req, res, next) => {
    if(config){
      return next();
    }
    request.get(req.webtaskContext.data.CONFIG_URL,
                {
                  headers: {
                    Authorization: req.webtaskContext.data['CONFIG_API_KEY']
                  }
                },
                (r, s, b) => {
                  if(s.statusCode !== 200){ return next('CONFIG. Cannot load configuration');}
                  config = JSON.parse(b);
                  //Override with local configuration parameters if needed. Merge those that are exclusive for this WT
                  config = _.extend(config, req.webtaskContext.data);
                  next();
                });
});

server.get('/snapshots/:id', (req, res) => { 
  var locals = {};
  async.series([
    //1. Connect to DB
    (cb) => {
      MongoClient.connect(config.MONGO_URL, (db_err, client) => {
        if(db_err){ cb(db_err); }
        locals.client = client;
        cb();
      });
    },
    //2. Query for images
    (cb) => {
      locals.client
            .db().collection('nest-snapshots')
                  .findOne({ snapshot_id: req.params.id },
                  (q_error, snapshot) => {
                    if(q_error){ return cb(q_error); }
                    locals.snapshot = snapshot;
                    cb();
                  });
    },
    //3. Process image
    (cb) => {
      var j = require('jimp');
      //Read Base64 stream, skipping the header
      j.read(new Buffer(locals.snapshot.image.substr(22), 'base64'), 
              (read_image_error, image) =>{
                if(read_image_error){ return cb(read_image_error); }
                res.set({'Content-Type': image.getMIME()});
                image.getBuffer(j.AUTO, 
                                (image_error, buffer) => {
                                  if(image_error){ return cb(image_error); }
                                  res.send(buffer);
                                  cb();
                                });
              });
    },
    //4. Delete image from db
    (cb) => {
        locals.client
            .db().collection('nest-snapshots')
                  .deleteOne({ snapshot_id: req.params.id },
                          (delete_error) => {
                            //we don't really care about delete failures
                            cb();  
                          });
    }
  ], (snapshot_error) => {
    if(snapshot_error){
      res.statusCode = 500;
      return res.send('Error getting SNAPSHOT', snapshot_error);
    }
  });
});

function uid(length, options) {
  var id = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  if(options && options.numericOnly){
    possible = "0123456789";
  }

  for (var i = 0; i < length; i++){
    id += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return id;
}

var requiresAuth = (req, res, next) => {
  if(req.session && req.session.nest_sms && req.session.nest_sms.user_id){
    return next();
  }
  next("Please login first");
};

//Login page to refresh the NEST token
server.get('/', (req, res, next) => {

  req.session.nest_sms = {
    state: uid(8),
    phone: req.query.phone
  };

  var authorizeParams = {
    client_id: req.webtaskContext.secrets.A0_CLIENT_ID,
    redirect_uri: util.format('https://%s/nest-sms/callback', req.hostname),
    scope: 'openid',
    response_type: 'code',
    state: req.session.nest_sms.state,
    connection: 'nest',
  };

  res.redirect('https://auth.eugeniopace.org/authorize?' + qs.stringify(authorizeParams));
});

//Handle OAuth2 callback handler
server.get('/callback', (req, res, next) => {

  if(req.session.nest_sms.state !== req.query.state){ return next(new Error('Invalid session')); }

  //Exchange code for token
  request.post(util.format('https://%s/oauth/token', config.A0_DOMAIN), {
    form:{
      grant_type: 'authorization_code',
      client_id: req.webtaskContext.secrets.A0_CLIENT_ID,
      client_secret: req.webtaskContext.secrets.A0_CLIENT_SECRET,
      redirect_uri: util.format('https://%s/nest-sms/callback', req.hostname),
      code: req.query.code
    }
  }, (e, s, b) => {
    //User is logged in with NEST. Associate phone with this user_id
    if(e) return next(e);
    if(s.statusCode === 200){
      var token = JSON.parse(b).id_token;
      var user = jwt.decode(token);
      req.session.nest_sms.user_id = user.sub;
      res.end(ejs.render(hereDoc(subscriptionForm), { 
                                                      phone: req.session.nest_sms.phone,
                                                      phone_subscribe_endpoint: util.format("https://%s/nest-sms/phone_subscription",req.hostname),
                                                      state: req.session.nest_sms.state
                                                    }));
    } else {
      next(new Error("There was an error in the enrollment (" + s.statusCode + ")"));
    }
  });
});

server.post('/phone_subscription', requiresAuth, (req, res, next)=>{
  if(req.session.nest_sms.state === req.body.state){
    var phone = req.body.phone;

    //Generates a simple 4 digit code & saves to local state tied to the user/phone
    var otp = uid(4, {numericOnly: true});
    sendSMSToRecipient({
                        sid: config.TW_ACCOUNT_SID,
                        token: config.TW_ACCOUNT_TOKEN
                        },
                        phone, "Your code is: " + otp, (e)=>{
      saveSubscriptionOTC(req.webtaskContext, phone, otp, (e)=>{
        if(e){
          req.session = null;
          return next(e);
        }
        req.session.nest_sms.phone = phone;
        res.end(ejs.render(hereDoc(otpForm), {
                                              phone_verify_endpoint: util.format("https://%s/nest-sms/phone_verify",req.hostname),
                                              state: req.session.nest_sms.state
                                            }));
      });
    });
  } else {
    req.session = null;
    next(new Error("Invalid session"));
  }
});

server.post('/phone_verify', requiresAuth, (req, res, next)=>{
  if(req.session.nest_sms.state === req.body.state){
    var locals = {};
    async.series([
        (cb)=>{
          //Check OTP & phone
          req.webtaskContext.storage.get((e, data) => {
            if(e){ cb(new Error('OTC cannot be retrieved', e)); }
            locals.data = data;
            var subscription_record = data[req.body.otp];
            if(!subscription_record){ return cb(new Error('Invalid OTP')); }
            if(subscription_record.phone !== req.session.nest_sms.phone){ return cb(new Error('Invalid phone/OTC')); }
            cb();
          });
        },
        (cb)=>{
          delete locals.data[req.body.otp];
          req.webtaskContext.storage.set(locals.data, (e) => {
            if(e){ return cb("Error updating OTP store", e); }
            cb();
          });
        },
        (cb)=>{
          getAuth0AccessToken(req.webtaskContext.secrets.A0_CLIENT_ID, req.webtaskContext.secrets.A0_CLIENT_SECRET, (e, token) => {
            if(e) { return cb(e); }
            locals.a0_access_token = token;
            cb();
          });
        },
        (cb)=>{
          //Update user app_metadata with phone
          request.patch(util.format('https://%s/api/v2/users/', config.A0_DOMAIN) + req.session.nest_sms.user_id, {
            headers: {
              Authorization: 'Bearer ' + locals.a0_access_token
          },
          json: {
            app_metadata: {
              phone: req.session.nest_sms.phone
            }
          }}, (e, s, b) => {
            if(e){ return cb(e); }
            if(s.statusCode !== 200){
              return cb(new Error('Updating user failed. Subscribe with the S command.'));
            }
            cb();
          });
        }
      ], (e) => {
        req.session = null;
        if(e){ return next(e); }
        res.end(ejs.render(hereDoc(genericMsgForm), { msg: "You are now subscribed! Send 'H' for  help on commands"}));
      });
  } else {
    req.session = null;
    next(new Error("Invalid session"));
  } 
});

function saveSubscriptionOTC(ctx, phone, otc, done){
  ctx.storage.get((error, data) => {
      if(error){ return done(error); }
      if(!data){ data = {}; }
      data[otc] = {
                    phone: phone,
                    created_at: new Date()
                  };
      ctx.storage.set(data, (error) => {
          if(error){ return done(error); }
          done(null);
      });
    });
}

function getCameraSnapshot(phone, name, done){
  var locals = {};
  locals.result = {};
  async.series([
      //Get an Auth0 Mgmt API Token to query user with the set phone
      (cb)=>{
        getAuth0AccessToken(config.A0_CLIENT_ID, config.A0_CLIENT_SECRET, (e, t) => {
          if(e) { return cb(e); }
          locals.access_token = t;
          //console.log(t);
          cb();
        });
      },
      //Locate the user with the phone
      (cb)=>{
        findUserByPhone(locals.access_token, phone, (e, user) => {
          if(e) { return cb(e); }
          locals.user = user;
          //console.log(user);
          cb();
        });
      },
      //Call NEST API with access_token
      (cb)=>{
        //console.log("Id",locals.user.identities[0]);
        request.get('https://developer-api.nest.com', {
            headers:{
              Authorization: 'Bearer ' + locals.user.identities[0].access_token,
            }
        }, (e, s, b) => {
          if(e){ return cb(e); }
          if(s.statusCode !== 200){
            return cb('Error calling NEST. Try subscribing again');
          }
          var NESTInfo = JSON.parse(b);
          var camera = _.find(NESTInfo.devices.cameras, (c)=>c.name.toLowerCase() === name.toLowerCase());
          if(!camera){ return cb('Camera not found'); }
          locals.camera = camera;
          //console.log(camera);
          cb();
        });
      },
      (cb)=>{
        var j = require('jimp');
        j.read(locals.camera.snapshot_url, (e, image)=>{
          if(e){ cb(e); }
          image.resize(450, j.AUTO);
          image.sepia();
          j.loadFont(j.FONT_SANS_64_WHITE, (e, font)=>{
            if(!e){
              image.print(font, 0, 0, name);
            } else {
              console.log(e);
            }
            image.getBase64(j.MIME_JPEG, (e, base64Image) => {
              if(e){ return cb(e); }
              locals.base64Image = base64Image;
              //console.log(base64Image);
              cb();
            });
          });
        });
      },
      (cb)=>{
        saveCompressedImage(phone, locals.base64Image, (e, url) => {
          if(e){ return cb(e);}
          console.log('saved to', url);
          locals.snapshot_url = url;
          cb();
        });
      }
    ], (e) => {
    if(e) { return done(new Error('CAMERA SNAPSHOT. Error getting snapshot', e)); }
    done(null, locals.snapshot_url);
  });
}

function saveCompressedImage(phone, image, done){
  var id = uid(20);
  MongoClient.connect(config.MONGO_URL, (err, client) => {
      if(err){ return done(err); }
      client.db().collection('nest-snapshots')
          .insertOne({
            snapshot_id: id,
            phone: phone,
            image: image          
          }, (e, r) => {
              client.close();
              if(e){ return done(err); }
              done(null, util.format('https://%s/nest-sms/snapshots/%s','wt-eugenio-pace-gmail-com-0.sandbox.auth0-extend.com',id));
          });
    });
}

function getTemperatures(phone, command, done){
  var locals = {};
  locals.result = {};
  async.series([
      //Get an Auth0 Mgmt API Token to query user with the set phone
      (cb)=>{
        getAuth0AccessToken(config.A0_CLIENT_ID, config.A0_CLIENT_SECRET, (e, t) => {
          if(e) { return cb(e); }
          locals.access_token = t;
          cb();
        });
      },
      //Locate the user with the phone
      (cb)=>{
        findUserByPhone(locals.access_token, phone, (e, user) => {
          if(e) { return cb(e); }
          locals.user = user;
          cb();
        });
      },
      //Call NEST API with access_token
      (cb)=>{
        //console.log("Id",locals.user.identities[0]);
        request.get('https://developer-api.nest.com',{
            headers:{ 
              Authorization: 'Bearer ' + locals.user.identities[0].access_token,
            }
        }, (e, s, b) => {
          if(e){ return cb(e); }
          if(s.statusCode !== 200){
            return cb('Error calling NEST. Try subscribing again');
          }
          var NESTInfo = JSON.parse(b);

          var thermostats = NESTInfo.devices.thermostats;

          //If no thermostat is specified, we return an array of all thermostats in the account
          if(!command){
            locals.result.thermostats = [];
            _.forOwn(thermostats,(t)=>{
              locals.result.thermostats.push(getTemperaturesFromThermostat(t));
            });  
          } else {
            locals.result.thermostat = getTemperaturesFromThermostat(_.find(thermostats, (t) => t.name.toLowerCase() === command.toLowerCase()));
          }
          cb();
        });
      }
    ], (e) => {
    if(e) { return done(e, 'Error getting temperature'); }
    done(null, locals.result);
  });
}

function getTemperaturesFromThermostat(thermostat){
  if(!thermostat){ return null; }
  return {
    ambient_t_c: thermostat.ambient_temperature_c,
    target_t_c: thermostat.target_temperature_c,
    name: thermostat.name,
    humidity: thermostat.humidity,
    state: thermostat.hvac_state
  };
}

function findUserByPhone(access_token, phone, done){
    request.get( util.format("https://%s/api/v2/users?per_page=1&connection=nest&q=app_metadata.phone%3A\"%s", config.A0_DOMAIN, encodeURIComponent(phone)),{
        headers: { Authorization: 'Bearer ' + access_token }
    }, (e, s, b) => { 
    console.log(b);
    if(e){ return done(e); }
    if(s.statusCode !== 200){ return done(new Error("Cannot find user. Did you subscribe?"), s.statusCode); }
    var users = JSON.parse(b);
    if(users.length === 0) { return done(new Error("User not found")); }
    done(e, JSON.parse(b)[0]);
  });
}

function setThermostatTemperature(phone, thermostatName, target_c, done){
  var locals = {};
  locals.result = {};
  async.series([
      //Get an Auth0 Mgmt API Token to query user with the set phone
      (cb)=>{
        getAuth0AccessToken(config.A0_CLIENT_ID, config.A0_CLIENT_SECRET, (e,t) => {
          if(e) { return cb(e); }
          locals.access_token = t;
          cb();
        });
      },
      //Locate the user with the phone
      (cb)=>{
        findUserByPhone(locals.access_token, phone, (e,user) => {
          if(e) { return cb(e); }
          if(!user) { return cb(new Error("No user was found!")); }
          locals.user = user;
          locals.nest_access_token = user.identities[0].access_token;
          cb();
        });
      },
      //Find te thermostats
      (cb)=>{
        request.get('https://developer-api.nest.com', {
            headers: { 
              Authorization: 'Bearer ' + locals.nest_access_token,
            }
        }, (e, s, b) => {
          if(e){ return cb(e); }
          var NESTInfo = JSON.parse(b);
          var thermostats = NESTInfo.devices.thermostats;
          locals.thermostat = _.find(thermostats,(t)=>t.name.toLowerCase() === thermostatName);
          if(!locals.thermostat){ return cb(new Error("Thermostat not found!")); }
          cb();
        });
      },
      //Call NEST API with access_token to change temperature
      (cb)=>{

        // console.log('Setting new T to ', target_c);
        // console.log('Th',locals.thermostat.device_id );
        // console.log('N at',locals.nest_access_token );

        request.put('https://developer-api.nest.com/devices/thermostats/' + locals.thermostat.device_id, {
            headers: {
              Authorization: 'Bearer ' + locals.nest_access_token,
            },
            followAllRedirects: true,
            json: {
              target_temperature_c: target_c
            }
        }, (e, s, b) => {
          if(e){ return cb(e); }
          if(s.statusCode !== 200){
            return cb(new Error(""));
          }
          cb(null);
        });
      }
    ], (e) => {
    if(e) { return done(e, 'Error setting temperature'); }  
    done(null, "New temperature set to " + target_c);    
  });
}

function getDevices(phone, done){
  var locals = {};
  locals.result = {};
  async.series([
      //Get an Auth0 Mgmt API Token to query user with the set phone
      (cb)=>{
        getAuth0AccessToken(config.A0_CLIENT_ID, config.A0_CLIENT_SECRET, (e, t) => {
          console.log(t);
          if(e) { return cb(e); }
          locals.access_token = t;
          cb();
        });
      },
      //Locate the user with the phone
      (cb)=>{
        findUserByPhone(locals.access_token, phone, (e,user) => {
          if(e) { return cb(e); }
          if(!user) { return cb(new Error("No user was found!")); }
          locals.user = user;
          locals.nest_access_token = user.identities[0].access_token;
          cb();
        });
      },
      //Find devices
      (cb)=>{
        request.get('https://developer-api.nest.com', {
            headers: {
              Authorization: 'Bearer ' + locals.nest_access_token,
            }
        }, (e, s, b) => {
          if(e){ return cb(e); }
          var NESTInfo = JSON.parse(b);
          locals.devices = {
            cameras: _.map(NESTInfo.devices.cameras,(c)=>c.name),
            thermostats: _.map(NESTInfo.devices.thermostats,(t)=>t.name)
          };
          console.log('Devices', locals.devices);
          cb();
        });
      }
    ], (e) => {
    if(e) { return done(e, 'Error getting devices'); }
    done(null, locals.devices);
  });  
}

// Uses Client Credentials to obtain a Mgmt API access_token that can quer
// user info 
function getAuth0AccessToken(client_id,client_secret,done){
  request.post(util.format('https://%s/oauth/token', config.A0_DOMAIN),{
    json: {
      client_id: client_id,
      client_secret: client_secret,
      audience: util.format("https://%s/api/v2/", config.A0_DOMAIN),
      grant_type: "client_credentials"
    }
  }, (e, s, b) => {
    if(s.statusCode !== 200){ return done(new Error('Cannot get an Auth0 access_token',e));}
    done(e, b.access_token);
  });
}

function formatThermostatInfo(thermostat){
  return util.format("%s thermostat is %s.\nAmbient T:%sC\nTarget:%sC\nHumidity:%s%%\n", thermostat.name,
                                                                                    thermostat.state,
                                                                                    thermostat.ambient_t_c,
                                                                                    thermostat.target_t_c,
                                                                                    thermostat.humidity);
}

/*------------ Twilio App Main ---------------*/
server.post('/sms', (req, res, next) => {
  var twilio = require('twilio');
  if(twilio.validateExpressRequest(req, config.TW_AUTH_TOKEN, {protocol: 'https'}) === false){
    return next('Unauthorized. Only accepts requests from Twilio.');
  }

  //Commands on SMS are of the format: {c} {args}
  var { verb, command } = parseInput(req);
  var phone = req.body.From;

  var menu = [
    {
      name: 'Get Current Temperature',
      help:
        '"t {zone}" {zone} is the _where_ your thermostat is as defined in NEST.',
      verbs: ['gt', 't'],
      handler: done => {
        getTemperatures(phone, command, (e, t) => {
                          if(e){ return done(e); }
                          //querying a specific Thermostat?
                          if(command){
                            if(t.thermostat){
                              done(null, formatThermostatInfo(t.thermostat));
                            } else {
                              done(null, util.format("You don't have a %s thermostat", command));
                            }
                          } else {
                            //send summary of all thermostats
                            var msg = "";
                            _.forEach(t.thermostats, (th)=>{
                              msg += formatThermostatInfo(th) + '\n';
                            });
                            done(null, msg);
                          }
                      });
      },
    },
    {
      name: 'Set Temperature',
      help:
        '"st {NAME} {T}" Sets temperature for thermostat {NAME} to {T} in C',
      verbs: ['st'],
      handler: done => {
        if(!command){ done(new Error("Command expects {THERM. NAME} {TEMP}"), "Invalid command"); }
        var data = command.split(' ');
        if(data.length !== 2){ done(new Error("Command expects {THERM. NAME} {TEMP}"), "Invalid command"); }
        var name = data[0];
        var target = parseFloat(data[1]);
        setThermostatTemperature(phone, name, target, done);
      },
    },
    {
      name: 'Snapshot',
      help:
        '"i {NAME}". Takes a snapshot of the camera {NAME}',
      verbs: ['i', 'snap', 'ss'],
      handler: done => {
        if(!command){ done(new Error("Command expects {CAMERA NAME}"),"Invalid command"); }
        getCameraSnapshot(phone, command, (e, url)=>{
                        done(e, "", url);
                      });
      },
    },
    {
      name: 'List devices',
      help:
        '"l". List all devices in the account',
      verbs: ['l', 'ld', 'ls'],
      handler: done => {
        getDevices(phone, (e, devices) => {
                        if(e) { return done(e); }
                        console.log('devices', devices);
                        done(e, util.format("Cameras:\n%s\n-\nThermostats:\n%s", devices.cameras.join('\n'), devices.thermostats.join('\n')));  
                      });
      },
    },
    {
      name: 'Subscribe',
      help:
        '"s". Subscribes this phone to a NEST account. Requires login with NEST.',
      verbs: ['s'],
      handler: done => {
        done(null, util.format("Please follow this link to subscribe:\nhttps://%s/nest-sms?phone=%s", req.hostname, encodeURIComponent(phone)));
      },
    },
    {
      name: 'Help',
      help: 'Get help on command. e.g. "h mood"',
      verbs: ['h', 'help'],
      handler: done => {
        //help
        if (!command) {
          return done(null, buildHelp(menu));
        }
        var menuEntry = findMenuEntry(menu, command);
        if (menuEntry) {
          done(null, menuEntry.help);
        } else {
          done(
            null,
            util.format(
              'Invalid command: [%s]\nAvailable commands:\n%s',
              command,
              buildHelp(menu)
            )
          );
        }
      },
    }
  ];

  var menuEntry = findMenuEntry(menu, verb);
  menuEntry.handler((e, msg, media_url) => {
    if(e){
      msg = util.format('ERROR: %s\n%s', msg, e);
    }
    sendSMSResponse(res, msg, media_url);
  });
});

/*------------Menu handling functions---------*/
//Menu functions
function findMenuEntry(menu, verb) {
  var menuEntry = _.find(menu, m => {
    return m.verbs.indexOf(verb) > -1;
  });
  if (!menuEntry) {
    menuEntry = {
      handler: done => {
        done(
          new Error('Invalid commmand'),
          util.format(
            'Command not recognized [%s]\n%s',
            verb,
            "For help, send 'h' command."
          )
        );
      },
    };
  }

  return menuEntry;
}

function buildHelp(menu) {
  return _.map(menu, m => {
    return m.verbs[0] + ' : ' + m.name;
  }).join('\n');
}

/*
  Accepted inputs are:
  {verb} {command}
  s 4 great  -> sleep 4 hours, note: great
  m 3 blues  -> mood 3, note: blues
*/
function parseInput(req) {
  var output = {};
  var input = req.body.Body.trim().toLowerCase();

  var separator = input.indexOf(' ');

  if (separator > 0) {
    output.verb = input.substring(0, separator).toLowerCase();
    output.command = input.substring(separator + 1);
  } else {
    output.verb = input.substring(0).toLowerCase();
    output.command = null;
  }

  return output;
}

/*------------Helper functions ---------------*/
function sendSMSResponse(res, msg, media_url) {
  var twilio = require('twilio');
  var twiml = new twilio.TwimlResponse();

  twiml.message(function() {
    this.body(msg);
    if(media_url){ this.media(media_url); }
  });

  res.writeHead(200, { 'Content-Type': 'text/xml' });
  res.end(twiml.toString());
}

function sendSMSToRecipient(twilioAuth, to, msg, done){
  var twilio = require('twilio')(twilioAuth.sid, twilioAuth.token);

  twilio.messages
          .create({
                    to: to,
                    from: "+14256573060",
                    body: msg,
                    }, done);
}

function subscriptionForm() {
  /*
<!DOCTYPE html>
<html>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<body>
<form method="POST" action="<%-phone_subscribe_endpoint%>">
  Confirm Phone:<br>
  <input type="text" name="phone" value="<%-phone%>">
  <input type="hidden" name="state" value="<%-state%>">
  <br>
  <input type="submit" value="Submit">
</form> 
</body>
</html>
*/
}

function otpForm() {
  /*
<!DOCTYPE html>
<html>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<body>
<form method="POST" action="<%-phone_verify_endpoint%>">
  OTP:<br>
  <input type="text" name="otp">
  <input type="hidden" name="state" value="<%-state%>">
  <br>
  <input type="submit" value="Submit">
</form> 
</body>
</html>
*/
}

function genericMsgForm() {
  /*
<!DOCTYPE html>
<html>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<body>
<%-msg%>
</body>
</html>
*/
}

function hereDoc(f) {
  return f
    .toString()
    .replace(/^[^\/]+\/\*!?/, '')
    .replace(/\*\/[^\/]+$/, '');
}

module.exports = Webtask.fromExpress(server);