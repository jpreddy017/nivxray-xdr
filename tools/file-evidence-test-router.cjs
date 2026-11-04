const React = require('react');
exports.useSearchParams = () => [new URLSearchParams(), () => {}];
exports.Link = ({children,to}) => React.createElement('a',{href:to},children);
