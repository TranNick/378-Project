'use strict';
module.exports = function(app){
	var key = require('../controllers/todoListController');

	app.route('/keypair')
		.post(key.post_pair);
	app.route('/private')
		.get(key.get_private);
	app.route('/keys')
		.get(key.all);
};

