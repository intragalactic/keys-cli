const platform = {

    endpoint: null,

    // descriptive name of the platform
    get_name: () => {
        return 'heroku';
    },

    // descriptive name of the environment equivalent, e.g. heroku: app, vault: namespace
    get_env_name: () => {
        return 'app';
    },

    // get env list ( to show in env-select )
    // sets model.user.envs
    envs: async(model) => {
        return Promise.resolve(model);
    },

    // returns { varkey1: { value: 'varval1'}, varkey2: { value: 'varval2'}  }
    env: async(envid) => {
        return {
            key1: {
                value: 'val1'
            },
            key2: {
                value: 'val2'
            }
        }
    },

    // update the remote platform with the --source env data
    push: async(envid, vars) => {

    }
}

module.exports = platform;