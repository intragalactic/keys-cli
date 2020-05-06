const ui = require('../ui');

const liaison = {

    get: (platform) => {

        switch (platform) {
            case 'heroku':
                return require('./heroku');
            case 'pivotal':
            case 'pcf':
            case 'cf':
                return require('./pivotal');
            default:
                ui.error('ERROR'.red, `Unknown platform ${platform}`);
                ui.info('Currently supported platforms: keys, heroku, pivotal');
                process.exit(1);
        }
    }
}

module.exports = liaison;