'use strict';

const path = require('path')
const { Gateway,Wallets } = require('fabric-network')
const fabricCAClient = require('fabric-ca-client')

const channelName = 'mychannel';
const chaincodeName = 'basic';
const mspOrg1 = 'Org1MSP';
const walletPath = path.join(__dirname, 'wallet');
const org1UserId = 'appUser';