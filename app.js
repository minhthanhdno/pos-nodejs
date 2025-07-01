var express = require('express');
var bodyParser = require('body-parser');
var session = require('express-session');
const cors = require('cors');




var underscore = require('underscore');
var https = require("https");
var http = require('http');
var fs = require("fs");
var async = require('async');
var app = express();
var compress = require('compression');
app.use(compress());

app.use(cors({
    allowedHeaders: ['Content-Type', 'Authorization', 'username', 'password'] // Thêm 'username' và 'password' vào danh sách các trường header cho phép
  }));
//
app.options('/*', function(req, res) {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,HEAD,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'content-Type,x-requested-with,X-Access-Token,Authorization');
    res.sendStatus(200);
});
app.use(function(req, res, next) {
	//allow cross domain
	res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,HEAD,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'content-Type,x-requested-with,X-Access-Token,Authorization');
    next();

});
var path = require("path");
app.use('/', express.static(__dirname + '/public'));
//app.use('/admin', express.static(__dirname + '/public'));
app.use('/templates', express.static(__dirname + '/templates'));
app.use('/images', express.static(__dirname + '/images'));
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json());
//
var server = http.createServer(app);
//route
var route = require('./route');
route(app);
//start server
var port = "3001";
server.listen(port, function() {
	console.log('server start at ' + port + ' port');
});
