'use strict';
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var KeySchema = new Schema({
	privatekey: {
		type: String,
		required: true,
		unique: true
	},
	publickey: {
		type: String,
		required: true,
		unique: true
	}
});

module.exports = mongoose.model('Keys', KeySchema);

