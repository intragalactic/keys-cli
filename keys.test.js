const cli = require('./keys');

test('config loaded', () => {
    let model = cli.model;
    cli.load_config(model)

    expect(model).toEqual(expect.objectContaining({
        local: expect.any(Boolean)
    }));

});