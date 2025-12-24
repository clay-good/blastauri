import _ from 'lodash';

function render(templateString, data) {
    // UNSAFE: _.template is in our KB
    const compiled = _.template(templateString);
    return compiled(data);
}

const tpl = 'Hello <%= user %>!';
console.log(render(tpl, { user: 'World' }));
