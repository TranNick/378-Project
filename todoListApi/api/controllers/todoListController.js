'use strict'; 

var mongoose = require('mongoose'),
	Key = mongoose.model('Keys');
/*
exports.list_all_tasks = function(req, res) {
	Task.find({}, function(err, task){ 
		if (err)
			res.send(err);
		res.json(task);
	});
};

exports.create_a_task = function(req, res){
	var new_task = new Task(req.body);
	new_task.save(function(err, task){
		if (err)
			res.send(err);
		res.json(task);
	});
};

exports.read_a_task = function(req, res){
	Task.findById(req.params.taskId, function(err, task){
		if (err)
			res.send(err);
		res.json(task);
	});
};

exports.update_a_task = function(req, res){
	Task.findOneAndUpdate({_id:  req.params.taskId}, req.body, {new: true}, function(err, task){
		if (err)
			res.send(err);
		res.json(task);
	});
};

exports.delete_a_task = function(req, res){
	Task.remove({
		_id: req.params.taskId
	}, function(err, task){
		if (err)
			res.send(err);
		res.json({message: 'Task successfully deleted'});
	});
};
*/

exports.all = function(req, res) {
	Key.find({}, function(err, key) {
		if(err)
			res.send(err);
		
		res.json(key);
	});
};

exports.post_pair = function(req, res) {
	if(req.headers.appkey != '378dnsecurity') {
		return res.status(500).send({success: false, message: 'That is not a trusted application.'});
	}

	Key.create({
		privatekey: req.body.privatekey,
		publickey: req.body.publickey
	},
	function(err, key){
		if(err)
			return res.status(500).send({success: false, error: err, message: 'There was a problem storing the key pair.'});

		res.status(200).send({success: true, message: 'Key pair stored.'});
	});
};

exports.get_private = function(req, res) {
	if(req.headers.appkey != '378dnsecurity') {
		return res.status(500).send({success: false, message: 'That is not a trusted application.'});
	}

	Key.findOne({
		publickey: req.headers.publickey
	},
	function(err, key) {
		if(err)
			res.send(err);

		if(!key) {
			res.status(500).send({success: false, message: 'No private key found for that public key.'});
		}
		else {
			res.status(200).send({success: true, privatekey: key.privatekey});
		}
	});
};
