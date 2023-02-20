'use strict'
const { Gateway } = require('fabric-network')
const utils=require("./utils.js")
const orgConfig=require("./connections/org1-config.json")

async function getContract(userId){
    const ccp = utils.buildCCPOrg(orgConfig.orgName); 
    const gateway = new Gateway();
    const wallet = await utils.buildWallet(); 

    try{
        await gateway.connect(ccp, {
            wallet,
            identity: userId,
            discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
        });

        const network = await gateway.getNetwork(orgConfig.channelName);
        const contract = network.getContract(orgConfig.chaincodeName);

        return contract
    }catch(err){
        console.log("Err: ", err)
        return err
    }
}

exports.EnrollCustomer = async function(userId, customerId, firstName, lastName, transitId){
    try{
      const contract = await getContract(userId)
      const response = await contract.submitTransaction("EnrollCustomer", customerId, firstName, lastName, transitId )
      return utils.prettyJSONString(response.toString());;

    }catch(err){
        return err
    }
}

exports.GetCustomer = async function(userId, customerId){
    try{
      const contract = await getContract(userId) 
      const response = await contract.submitTransaction("GetCustomer", customerId)
      return utils.prettyJSONString(response.toString());
    }catch(err){
        return err
    }
}