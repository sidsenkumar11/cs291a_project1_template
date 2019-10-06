# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

  # Check for invalid paths
  if event['path'] != '/' && event['path'] != '/token'
    return response(status: 404)
  end

  # Check for invalid HTTP method for each path
  if event['httpMethod'] == 'GET' && event['path'] == '/'

    if event['headers'].key?('Authorization')

      # Check valid JWT
      begin
        payload = JWT.decode(event['headers']['Authorization'][7..-1], ENV['JWT_SECRET'], true)
      rescue JWT::ExpiredSignature => e
        return response(status: 401)
      rescue JWT::ImmatureSignature => e
        return response(status: 401)
      rescue JWT::DecodeError => e
        return response(status: 403)
      end

      # Reflect data
      return response(body: payload[0]['data'], status: 200)

    else
      return response(status: 403)
    end

  elsif event['httpMethod'] == 'POST' && event['path'] == '/token'

    # Get "Content-Type" header
    content_type_header = ''
    event['headers'].each_key do |key|
      if key.strip.casecmp?('Content-Type')
        content_type_header = key
        break
      end
    end

    # Check Content-Type header for application/json
    if event['headers'][content_type_header].strip != 'application/json'
      return response(status: 415)
    end

    # Check if body is actually json
    if !event.key?('body')
      return response(status: 422)
    end

    begin
      body = JSON.parse(event['body'].to_s)
    rescue JSON::ParserError => e
      return response(status: 422)
    end

    # Generate a token and send!
    payload = {
      data: body,
      exp: Time.now.to_i + 5,
      nbf: Time.now.to_i + 2
    }
    token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
    response(body: {'token' => token }, status: 201)
  else
    response(status: 405)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
