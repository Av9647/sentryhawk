function handler(event) {
  'use strict';
  var request = event.request;
  var uri     = request.uri;
  var headers = request.headers;
  var host    = (headers.host && headers.host.value.toLowerCase()) || '';

  if (host === 'sentryhawk.org') {
    return {
      statusCode: 301,
      statusDescription: 'Moved Permanently',
      headers: {
        'location': { value: 'https://www.sentryhawk.org' }
      }
    };
  }

  if (uri === '/' || uri === '/index.html') {
    request.uri = '/superset/index.html';
    return request;
  }

  if (
       uri.indexOf('/superset/static/') === 0 ||
       uri.indexOf('/superset/assets/') === 0 ||
       uri === '/favicon.ico' ||
       uri === '/robots.txt'
  ) {
    return request;
  }

  return request;
}
