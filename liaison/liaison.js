const ui = require('../ui');

const liaison = {

    get_source: (platform) => {

        switch (platform) {
            case 'heroku':
                return require('./heroku');
            default:
                ui.error('ERROR'.red, `Unknown source ${platform}`);
                process.exit(1);
        }
    },

    get_destination: (platform) => {

        switch (platform) {
            case 'heroku':
                return require('./heroku');
            default:
                ui.error('ERROR'.red, `Unknown destination ${platform}`);
                process.exit(1);
        }
    }
}

module.exports = liaison;