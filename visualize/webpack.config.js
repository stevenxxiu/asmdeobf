const ExtractTextPlugin = require('extract-text-webpack-plugin')
const OpenBrowserPlugin = require('open-browser-webpack-plugin')
const webpack = require('webpack')
const {resolve} = require('path')

module.exports = {
  devtool: 'cheap-module-eval-source-map',
  entry: [
    'react-hot-loader/patch',
    'webpack-dev-server/client?http://localhost:8080',
    'webpack/hot/only-dev-server',
    './main.js',
    './assets/scss/main.scss',
  ],
  output: {
    filename: 'bundle.js',
    path: resolve(__dirname, 'dist'),
    publicPath: '/',
  },
  context: resolve(__dirname, 'app'),
  devServer: {
    hot: true,
    contentBase: resolve(__dirname, 'build'),
    publicPath: '/',
  },
  resolveLoader: {modules: ['node_modules', '.']},
  module: {
    rules: [{
      test: /\.scss$/,
      include: resolve(__dirname, 'app'),
      use: ['css-hot-loader'].concat(ExtractTextPlugin.extract({
        use: [
          {loader: 'css-loader'},
          {loader: 'postcss-loader', options: {config: {ctx: {autoprefixer: {browsers: ['last 2 versions']}}}}},
          {loader: 'sass-loader', options: {indentedSyntax: true}},
          'presass-loader',
        ],
        publicPath: '../',
      })),
    }, {
      test: /\.js$/,
      include: resolve(__dirname, 'app'),
      use: ['babel-loader'],
    }],
  },
  plugins: [
    new webpack.optimize.ModuleConcatenationPlugin(),
    new webpack.HotModuleReplacementPlugin(),
    new ExtractTextPlugin({filename: './styles/style.css', disable: false, allChunks: true}),
    new OpenBrowserPlugin({url: 'http://localhost:8080'}),
  ],
}
