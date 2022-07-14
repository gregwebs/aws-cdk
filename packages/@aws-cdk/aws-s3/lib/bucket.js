"use strict";
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReplaceKey = exports.BucketAccessControl = exports.EventType = exports.BucketEncryption = exports.Bucket = exports.ObjectOwnership = exports.InventoryObjectVersion = exports.InventoryFrequency = exports.InventoryFormat = exports.RedirectProtocol = exports.HttpMethods = exports.BlockPublicAccess = exports.BucketBase = void 0;
const jsiiDeprecationWarnings = require("../.warnings.jsii.js");
const JSII_RTTI_SYMBOL_1 = Symbol.for("jsii.rtti");
const os_1 = require("os");
const path = require("path");
const events = require("@aws-cdk/aws-events");
const iam = require("@aws-cdk/aws-iam");
const kms = require("@aws-cdk/aws-kms");
const core_1 = require("@aws-cdk/core");
const cxapi = require("@aws-cdk/cx-api");
const bucket_policy_1 = require("./bucket-policy");
const notifications_resource_1 = require("./notifications-resource");
const perms = require("./perms");
const s3_generated_1 = require("./s3.generated");
const util_1 = require("./util");
const AUTO_DELETE_OBJECTS_RESOURCE_TYPE = 'Custom::S3AutoDeleteObjects';
const AUTO_DELETE_OBJECTS_TAG = 'aws-cdk:auto-delete-objects';
/**
 * Represents an S3 Bucket.
 *
 * Buckets can be either defined within this stack:
 *
 *   new Bucket(this, 'MyBucket', { props });
 *
 * Or imported from an existing bucket:
 *
 *   Bucket.import(this, 'MyImportedBucket', { bucketArn: ... });
 *
 * You can also export a bucket and import it into another stack:
 *
 *   const ref = myBucket.export();
 *   Bucket.import(this, 'MyImportedBucket', ref);
 *
 */
class BucketBase extends core_1.Resource {
    constructor(scope, id, props = {}) {
        super(scope, id, props);
        this.node.addValidation({ validate: () => this.policy?.document.validateForResourcePolicy() ?? [] });
    }
    /**
     * Define a CloudWatch event that triggers when something happens to this repository
     *
     * Requires that there exists at least one CloudTrail Trail in your account
     * that captures the event. This method will not create the Trail.
     *
     * @param id The id of the rule
     * @param options Options for adding the rule
     */
    onCloudTrailEvent(id, options = {}) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_OnCloudTrailBucketEventOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.onCloudTrailEvent);
            }
            throw error;
        }
        const rule = new events.Rule(this, id, options);
        rule.addTarget(options.target);
        rule.addEventPattern({
            source: ['aws.s3'],
            detailType: ['AWS API Call via CloudTrail'],
            detail: {
                resources: {
                    ARN: options.paths?.map(p => this.arnForObjects(p)) ?? [this.bucketArn],
                },
            },
        });
        return rule;
    }
    /**
     * Defines an AWS CloudWatch event that triggers when an object is uploaded
     * to the specified paths (keys) in this bucket using the PutObject API call.
     *
     * Note that some tools like `aws s3 cp` will automatically use either
     * PutObject or the multipart upload API depending on the file size,
     * so using `onCloudTrailWriteObject` may be preferable.
     *
     * Requires that there exists at least one CloudTrail Trail in your account
     * that captures the event. This method will not create the Trail.
     *
     * @param id The id of the rule
     * @param options Options for adding the rule
     */
    onCloudTrailPutObject(id, options = {}) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_OnCloudTrailBucketEventOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.onCloudTrailPutObject);
            }
            throw error;
        }
        const rule = this.onCloudTrailEvent(id, options);
        rule.addEventPattern({
            detail: {
                eventName: ['PutObject'],
            },
        });
        return rule;
    }
    /**
     * Defines an AWS CloudWatch event that triggers when an object at the
     * specified paths (keys) in this bucket are written to.  This includes
     * the events PutObject, CopyObject, and CompleteMultipartUpload.
     *
     * Note that some tools like `aws s3 cp` will automatically use either
     * PutObject or the multipart upload API depending on the file size,
     * so using this method may be preferable to `onCloudTrailPutObject`.
     *
     * Requires that there exists at least one CloudTrail Trail in your account
     * that captures the event. This method will not create the Trail.
     *
     * @param id The id of the rule
     * @param options Options for adding the rule
     */
    onCloudTrailWriteObject(id, options = {}) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_OnCloudTrailBucketEventOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.onCloudTrailWriteObject);
            }
            throw error;
        }
        const rule = this.onCloudTrailEvent(id, options);
        rule.addEventPattern({
            detail: {
                eventName: [
                    'CompleteMultipartUpload',
                    'CopyObject',
                    'PutObject',
                ],
                requestParameters: {
                    bucketName: [this.bucketName],
                    key: options.paths,
                },
            },
        });
        return rule;
    }
    /**
     * Adds a statement to the resource policy for a principal (i.e.
     * account/role/service) to perform actions on this bucket and/or its
     * contents. Use `bucketArn` and `arnForObjects(keys)` to obtain ARNs for
     * this bucket or objects.
     *
     * Note that the policy statement may or may not be added to the policy.
     * For example, when an `IBucket` is created from an existing bucket,
     * it's not possible to tell whether the bucket already has a policy
     * attached, let alone to re-use that policy to add more statements to it.
     * So it's safest to do nothing in these cases.
     *
     * @param permission the policy statement to be added to the bucket's
     * policy.
     * @returns metadata about the execution of this method. If the policy
     * was not added, the value of `statementAdded` will be `false`. You
     * should always check this value to make sure that the operation was
     * actually carried out. Otherwise, synthesis and deploy will terminate
     * silently, which may be confusing.
     */
    addToResourcePolicy(permission) {
        if (!this.policy && this.autoCreatePolicy) {
            this.policy = new bucket_policy_1.BucketPolicy(this, 'Policy', { bucket: this });
        }
        if (this.policy) {
            this.policy.document.addStatements(permission);
            return { statementAdded: true, policyDependable: this.policy };
        }
        return { statementAdded: false };
    }
    /**
     * The https URL of an S3 object. Specify `regional: false` at the options
     * for non-regional URLs. For example:
     *
     * - `https://s3.us-west-1.amazonaws.com/onlybucket`
     * - `https://s3.us-west-1.amazonaws.com/bucket/key`
     * - `https://s3.cn-north-1.amazonaws.com.cn/china-bucket/mykey`
     *
     * @param key The S3 key of the object. If not specified, the URL of the
     *      bucket is returned.
     * @returns an ObjectS3Url token
     */
    urlForObject(key) {
        const stack = core_1.Stack.of(this);
        const prefix = `https://s3.${this.env.region}.${stack.urlSuffix}/`;
        if (typeof key !== 'string') {
            return this.urlJoin(prefix, this.bucketName);
        }
        return this.urlJoin(prefix, this.bucketName, key);
    }
    /**
     * The https Transfer Acceleration URL of an S3 object. Specify `dualStack: true` at the options
     * for dual-stack endpoint (connect to the bucket over IPv6). For example:
     *
     * - `https://bucket.s3-accelerate.amazonaws.com`
     * - `https://bucket.s3-accelerate.amazonaws.com/key`
     *
     * @param key The S3 key of the object. If not specified, the URL of the
     *      bucket is returned.
     * @param options Options for generating URL.
     * @returns an TransferAccelerationUrl token
     */
    transferAccelerationUrlForObject(key, options) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_TransferAccelerationUrlOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.transferAccelerationUrlForObject);
            }
            throw error;
        }
        const dualStack = options?.dualStack ? '.dualstack' : '';
        const prefix = `https://${this.bucketName}.s3-accelerate${dualStack}.amazonaws.com/`;
        if (typeof key !== 'string') {
            return this.urlJoin(prefix);
        }
        return this.urlJoin(prefix, key);
    }
    /**
     * The virtual hosted-style URL of an S3 object. Specify `regional: false` at
     * the options for non-regional URL. For example:
     *
     * - `https://only-bucket.s3.us-west-1.amazonaws.com`
     * - `https://bucket.s3.us-west-1.amazonaws.com/key`
     * - `https://bucket.s3.amazonaws.com/key`
     * - `https://china-bucket.s3.cn-north-1.amazonaws.com.cn/mykey`
     *
     * @param key The S3 key of the object. If not specified, the URL of the
     *      bucket is returned.
     * @param options Options for generating URL.
     * @returns an ObjectS3Url token
     */
    virtualHostedUrlForObject(key, options) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_VirtualHostedStyleUrlOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.virtualHostedUrlForObject);
            }
            throw error;
        }
        const domainName = options?.regional ?? true ? this.bucketRegionalDomainName : this.bucketDomainName;
        const prefix = `https://${domainName}`;
        if (typeof key !== 'string') {
            return prefix;
        }
        return this.urlJoin(prefix, key);
    }
    /**
     * The S3 URL of an S3 object. For example:
     *
     * - `s3://onlybucket`
     * - `s3://bucket/key`
     *
     * @param key The S3 key of the object. If not specified, the S3 URL of the
     *      bucket is returned.
     * @returns an ObjectS3Url token
     */
    s3UrlForObject(key) {
        const prefix = 's3://';
        if (typeof key !== 'string') {
            return this.urlJoin(prefix, this.bucketName);
        }
        return this.urlJoin(prefix, this.bucketName, key);
    }
    /**
     * Returns an ARN that represents all objects within the bucket that match
     * the key pattern specified. To represent all keys, specify ``"*"``.
     *
     * If you need to specify a keyPattern with multiple components, concatenate them into a single string, e.g.:
     *
     *   arnForObjects(`home/${team}/${user}/*`)
     *
     */
    arnForObjects(keyPattern) {
        return `${this.bucketArn}/${keyPattern}`;
    }
    /**
     * Grant read permissions for this bucket and it's contents to an IAM
     * principal (Role/Group/User).
     *
     * If encryption is used, permission to use the key to decrypt the contents
     * of the bucket will also be granted to the same principal.
     *
     * @param identity The principal
     * @param objectsKeyPattern Restrict the permission to a certain key pattern (default '*')
     */
    grantRead(identity, objectsKeyPattern = '*') {
        return this.grant(identity, perms.BUCKET_READ_ACTIONS, perms.KEY_READ_ACTIONS, this.bucketArn, this.arnForObjects(objectsKeyPattern));
    }
    grantWrite(identity, objectsKeyPattern = '*') {
        return this.grant(identity, this.writeActions, perms.KEY_WRITE_ACTIONS, this.bucketArn, this.arnForObjects(objectsKeyPattern));
    }
    /**
     * Grants s3:PutObject* and s3:Abort* permissions for this bucket to an IAM principal.
     *
     * If encryption is used, permission to use the key to encrypt the contents
     * of written files will also be granted to the same principal.
     * @param identity The principal
     * @param objectsKeyPattern Restrict the permission to a certain key pattern (default '*')
     */
    grantPut(identity, objectsKeyPattern = '*') {
        return this.grant(identity, this.putActions, perms.KEY_WRITE_ACTIONS, this.arnForObjects(objectsKeyPattern));
    }
    grantPutAcl(identity, objectsKeyPattern = '*') {
        return this.grant(identity, perms.BUCKET_PUT_ACL_ACTIONS, [], this.arnForObjects(objectsKeyPattern));
    }
    /**
     * Grants s3:DeleteObject* permission to an IAM principal for objects
     * in this bucket.
     *
     * @param identity The principal
     * @param objectsKeyPattern Restrict the permission to a certain key pattern (default '*')
     */
    grantDelete(identity, objectsKeyPattern = '*') {
        return this.grant(identity, perms.BUCKET_DELETE_ACTIONS, [], this.arnForObjects(objectsKeyPattern));
    }
    grantReadWrite(identity, objectsKeyPattern = '*') {
        const bucketActions = perms.BUCKET_READ_ACTIONS.concat(this.writeActions);
        // we need unique permissions because some permissions are common between read and write key actions
        const keyActions = [...new Set([...perms.KEY_READ_ACTIONS, ...perms.KEY_WRITE_ACTIONS])];
        return this.grant(identity, bucketActions, keyActions, this.bucketArn, this.arnForObjects(objectsKeyPattern));
    }
    /**
     * Allows unrestricted access to objects from this bucket.
     *
     * IMPORTANT: This permission allows anyone to perform actions on S3 objects
     * in this bucket, which is useful for when you configure your bucket as a
     * website and want everyone to be able to read objects in the bucket without
     * needing to authenticate.
     *
     * Without arguments, this method will grant read ("s3:GetObject") access to
     * all objects ("*") in the bucket.
     *
     * The method returns the `iam.Grant` object, which can then be modified
     * as needed. For example, you can add a condition that will restrict access only
     * to an IPv4 range like this:
     *
     *     const grant = bucket.grantPublicAccess();
     *     grant.resourceStatement!.addCondition(‘IpAddress’, { “aws:SourceIp”: “54.240.143.0/24” });
     *
     * Note that if this `IBucket` refers to an existing bucket, possibly not
     * managed by CloudFormation, this method will have no effect, since it's
     * impossible to modify the policy of an existing bucket.
     *
     * @param keyPrefix the prefix of S3 object keys (e.g. `home/*`). Default is "*".
     * @param allowedActions the set of S3 actions to allow. Default is "s3:GetObject".
     */
    grantPublicAccess(keyPrefix = '*', ...allowedActions) {
        if (this.disallowPublicAccess) {
            throw new Error("Cannot grant public access when 'blockPublicPolicy' is enabled");
        }
        allowedActions = allowedActions.length > 0 ? allowedActions : ['s3:GetObject'];
        return iam.Grant.addToPrincipalOrResource({
            actions: allowedActions,
            resourceArns: [this.arnForObjects(keyPrefix)],
            grantee: new iam.AnyPrincipal(),
            resource: this,
        });
    }
    /**
     * Adds a bucket notification event destination.
     * @param event The event to trigger the notification
     * @param dest The notification destination (Lambda, SNS Topic or SQS Queue)
     *
     * @param filters S3 object key filter rules to determine which objects
     * trigger this event. Each filter must include a `prefix` and/or `suffix`
     * that will be matched against the s3 object key. Refer to the S3 Developer Guide
     * for details about allowed filter rules.
     *
     * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html#notification-how-to-filtering
     *
     * @example
     *
     *    declare const myLambda: lambda.Function;
     *    const bucket = new s3.Bucket(this, 'MyBucket');
     *    bucket.addEventNotification(s3.EventType.OBJECT_CREATED, new s3n.LambdaDestination(myLambda), {prefix: 'home/myusername/*'});
     *
     * @see
     * https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
     */
    addEventNotification(event, dest, ...filters) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_EventType(event);
            jsiiDeprecationWarnings._aws_cdk_aws_s3_IBucketNotificationDestination(dest);
            jsiiDeprecationWarnings._aws_cdk_aws_s3_NotificationKeyFilter(filters);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addEventNotification);
            }
            throw error;
        }
        this.withNotifications(notifications => notifications.addNotification(event, dest, ...filters));
    }
    withNotifications(cb) {
        if (!this.notifications) {
            this.notifications = new notifications_resource_1.BucketNotifications(this, 'Notifications', {
                bucket: this,
                handlerRole: this.notificationsHandlerRole,
            });
        }
        cb(this.notifications);
    }
    /**
     * Subscribes a destination to receive notifications when an object is
     * created in the bucket. This is identical to calling
     * `onEvent(EventType.OBJECT_CREATED)`.
     *
     * @param dest The notification destination (see onEvent)
     * @param filters Filters (see onEvent)
     */
    addObjectCreatedNotification(dest, ...filters) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_IBucketNotificationDestination(dest);
            jsiiDeprecationWarnings._aws_cdk_aws_s3_NotificationKeyFilter(filters);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addObjectCreatedNotification);
            }
            throw error;
        }
        return this.addEventNotification(EventType.OBJECT_CREATED, dest, ...filters);
    }
    /**
     * Subscribes a destination to receive notifications when an object is
     * removed from the bucket. This is identical to calling
     * `onEvent(EventType.OBJECT_REMOVED)`.
     *
     * @param dest The notification destination (see onEvent)
     * @param filters Filters (see onEvent)
     */
    addObjectRemovedNotification(dest, ...filters) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_IBucketNotificationDestination(dest);
            jsiiDeprecationWarnings._aws_cdk_aws_s3_NotificationKeyFilter(filters);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addObjectRemovedNotification);
            }
            throw error;
        }
        return this.addEventNotification(EventType.OBJECT_REMOVED, dest, ...filters);
    }
    /**
     * Enables event bridge notification, causing all events below to be sent to EventBridge:
     *
     * - Object Deleted (DeleteObject)
     * - Object Deleted (Lifecycle expiration)
     * - Object Restore Initiated
     * - Object Restore Completed
     * - Object Restore Expired
     * - Object Storage Class Changed
     * - Object Access Tier Changed
     * - Object ACL Updated
     * - Object Tags Added
     * - Object Tags Deleted
     */
    enableEventBridgeNotification() {
        this.withNotifications(notifications => notifications.enableEventBridgeNotification());
    }
    get writeActions() {
        return [
            ...perms.BUCKET_DELETE_ACTIONS,
            ...this.putActions,
        ];
    }
    get putActions() {
        return core_1.FeatureFlags.of(this).isEnabled(cxapi.S3_GRANT_WRITE_WITHOUT_ACL)
            ? perms.BUCKET_PUT_ACTIONS
            : perms.LEGACY_BUCKET_PUT_ACTIONS;
    }
    urlJoin(...components) {
        return components.reduce((result, component) => {
            if (result.endsWith('/')) {
                result = result.slice(0, -1);
            }
            if (component.startsWith('/')) {
                component = component.slice(1);
            }
            return `${result}/${component}`;
        });
    }
    grant(grantee, bucketActions, keyActions, resourceArn, ...otherResourceArns) {
        const resources = [resourceArn, ...otherResourceArns];
        const ret = iam.Grant.addToPrincipalOrResource({
            grantee,
            actions: bucketActions,
            resourceArns: resources,
            resource: this,
        });
        if (this.encryptionKey && keyActions && keyActions.length !== 0) {
            this.encryptionKey.grant(grantee, ...keyActions);
        }
        return ret;
    }
}
exports.BucketBase = BucketBase;
_a = JSII_RTTI_SYMBOL_1;
BucketBase[_a] = { fqn: "@aws-cdk/aws-s3.BucketBase", version: "0.0.0" };
class BlockPublicAccess {
    constructor(options) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_BlockPublicAccessOptions(options);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, BlockPublicAccess);
            }
            throw error;
        }
        this.blockPublicAcls = options.blockPublicAcls;
        this.blockPublicPolicy = options.blockPublicPolicy;
        this.ignorePublicAcls = options.ignorePublicAcls;
        this.restrictPublicBuckets = options.restrictPublicBuckets;
    }
}
exports.BlockPublicAccess = BlockPublicAccess;
_b = JSII_RTTI_SYMBOL_1;
BlockPublicAccess[_b] = { fqn: "@aws-cdk/aws-s3.BlockPublicAccess", version: "0.0.0" };
BlockPublicAccess.BLOCK_ALL = new BlockPublicAccess({
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});
BlockPublicAccess.BLOCK_ACLS = new BlockPublicAccess({
    blockPublicAcls: true,
    ignorePublicAcls: true,
});
/**
 * All http request methods
 */
var HttpMethods;
(function (HttpMethods) {
    /**
     * The GET method requests a representation of the specified resource.
     */
    HttpMethods["GET"] = "GET";
    /**
     * The PUT method replaces all current representations of the target resource with the request payload.
     */
    HttpMethods["PUT"] = "PUT";
    /**
     * The HEAD method asks for a response identical to that of a GET request, but without the response body.
     */
    HttpMethods["HEAD"] = "HEAD";
    /**
     * The POST method is used to submit an entity to the specified resource, often causing a change in state or side effects on the server.
     */
    HttpMethods["POST"] = "POST";
    /**
     * The DELETE method deletes the specified resource.
     */
    HttpMethods["DELETE"] = "DELETE";
})(HttpMethods = exports.HttpMethods || (exports.HttpMethods = {}));
/**
 * All http request methods
 */
var RedirectProtocol;
(function (RedirectProtocol) {
    RedirectProtocol["HTTP"] = "http";
    RedirectProtocol["HTTPS"] = "https";
})(RedirectProtocol = exports.RedirectProtocol || (exports.RedirectProtocol = {}));
/**
 * All supported inventory list formats.
 */
var InventoryFormat;
(function (InventoryFormat) {
    /**
     * Generate the inventory list as CSV.
     */
    InventoryFormat["CSV"] = "CSV";
    /**
     * Generate the inventory list as Parquet.
     */
    InventoryFormat["PARQUET"] = "Parquet";
    /**
     * Generate the inventory list as ORC.
     */
    InventoryFormat["ORC"] = "ORC";
})(InventoryFormat = exports.InventoryFormat || (exports.InventoryFormat = {}));
/**
 * All supported inventory frequencies.
 */
var InventoryFrequency;
(function (InventoryFrequency) {
    /**
     * A report is generated every day.
     */
    InventoryFrequency["DAILY"] = "Daily";
    /**
     * A report is generated every Sunday (UTC timezone) after the initial report.
     */
    InventoryFrequency["WEEKLY"] = "Weekly";
})(InventoryFrequency = exports.InventoryFrequency || (exports.InventoryFrequency = {}));
/**
 * Inventory version support.
 */
var InventoryObjectVersion;
(function (InventoryObjectVersion) {
    /**
     * Includes all versions of each object in the report.
     */
    InventoryObjectVersion["ALL"] = "All";
    /**
     * Includes only the current version of each object in the report.
     */
    InventoryObjectVersion["CURRENT"] = "Current";
})(InventoryObjectVersion = exports.InventoryObjectVersion || (exports.InventoryObjectVersion = {}));
/**
   * The ObjectOwnership of the bucket.
   *
   * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/about-object-ownership.html
   *
   */
var ObjectOwnership;
(function (ObjectOwnership) {
    /**
     * ACLs are disabled, and the bucket owner automatically owns
     * and has full control over every object in the bucket.
     * ACLs no longer affect permissions to data in the S3 bucket.
     * The bucket uses policies to define access control.
     */
    ObjectOwnership["BUCKET_OWNER_ENFORCED"] = "BucketOwnerEnforced";
    /**
     * Objects uploaded to the bucket change ownership to the bucket owner .
     */
    ObjectOwnership["BUCKET_OWNER_PREFERRED"] = "BucketOwnerPreferred";
    /**
     * The uploading account will own the object.
     */
    ObjectOwnership["OBJECT_WRITER"] = "ObjectWriter";
})(ObjectOwnership = exports.ObjectOwnership || (exports.ObjectOwnership = {}));
/**
 * An S3 bucket with associated policy objects
 *
 * This bucket does not yet have all features that exposed by the underlying
 * BucketResource.
 *
 * @example
 *
 * new Bucket(scope, 'Bucket', {
 *   blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
 *   encryption: BucketEncryption.S3_MANAGED,
 *   enforceSSL: true,
 *   versioned: true,
 *   removalPolicy: RemovalPolicy.RETAIN,
 * });
 *
 */
class Bucket extends BucketBase {
    constructor(scope, id, props = {}) {
        super(scope, id, {
            physicalName: props.bucketName,
        });
        this.autoCreatePolicy = true;
        this.lifecycleRules = [];
        this.metrics = [];
        this.cors = [];
        this.inventories = [];
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_BucketProps(props);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, Bucket);
            }
            throw error;
        }
        this.notificationsHandlerRole = props.notificationsHandlerRole;
        const { bucketEncryption, encryptionKey } = this.parseEncryption(props);
        Bucket.validateBucketName(this.physicalName);
        const websiteConfiguration = this.renderWebsiteConfiguration(props);
        this.isWebsite = (websiteConfiguration !== undefined);
        const resource = new s3_generated_1.CfnBucket(this, 'Resource', {
            bucketName: this.physicalName,
            bucketEncryption,
            versioningConfiguration: props.versioned ? { status: 'Enabled' } : undefined,
            lifecycleConfiguration: core_1.Lazy.any({ produce: () => this.parseLifecycleConfiguration() }),
            websiteConfiguration,
            publicAccessBlockConfiguration: props.blockPublicAccess,
            metricsConfigurations: core_1.Lazy.any({ produce: () => this.parseMetricConfiguration() }),
            corsConfiguration: core_1.Lazy.any({ produce: () => this.parseCorsConfiguration() }),
            accessControl: core_1.Lazy.string({ produce: () => this.accessControl }),
            loggingConfiguration: this.parseServerAccessLogs(props),
            inventoryConfigurations: core_1.Lazy.any({ produce: () => this.parseInventoryConfiguration() }),
            ownershipControls: this.parseOwnershipControls(props),
            accelerateConfiguration: props.transferAcceleration ? { accelerationStatus: 'Enabled' } : undefined,
            intelligentTieringConfigurations: this.parseTieringConfig(props),
        });
        this._resource = resource;
        resource.applyRemovalPolicy(props.removalPolicy);
        this.versioned = props.versioned;
        this.encryptionKey = encryptionKey;
        this.eventBridgeEnabled = props.eventBridgeEnabled;
        this.bucketName = this.getResourceNameAttribute(resource.ref);
        this.bucketArn = this.getResourceArnAttribute(resource.attrArn, {
            region: '',
            account: '',
            service: 's3',
            resource: this.physicalName,
        });
        this.bucketDomainName = resource.attrDomainName;
        this.bucketWebsiteUrl = resource.attrWebsiteUrl;
        this.bucketWebsiteDomainName = core_1.Fn.select(2, core_1.Fn.split('/', this.bucketWebsiteUrl));
        this.bucketDualStackDomainName = resource.attrDualStackDomainName;
        this.bucketRegionalDomainName = resource.attrRegionalDomainName;
        this.disallowPublicAccess = props.blockPublicAccess && props.blockPublicAccess.blockPublicPolicy;
        this.accessControl = props.accessControl;
        // Enforce AWS Foundational Security Best Practice
        if (props.enforceSSL) {
            this.enforceSSLStatement();
        }
        if (props.serverAccessLogsBucket instanceof Bucket) {
            props.serverAccessLogsBucket.allowLogDelivery();
        }
        for (const inventory of props.inventories ?? []) {
            this.addInventory(inventory);
        }
        // Add all bucket metric configurations rules
        (props.metrics || []).forEach(this.addMetric.bind(this));
        // Add all cors configuration rules
        (props.cors || []).forEach(this.addCorsRule.bind(this));
        // Add all lifecycle rules
        (props.lifecycleRules || []).forEach(this.addLifecycleRule.bind(this));
        if (props.publicReadAccess) {
            this.grantPublicAccess();
        }
        if (props.autoDeleteObjects) {
            if (props.removalPolicy !== core_1.RemovalPolicy.DESTROY) {
                throw new Error('Cannot use \'autoDeleteObjects\' property on a bucket without setting removal policy to \'DESTROY\'.');
            }
            this.enableAutoDeleteObjects();
        }
        if (this.eventBridgeEnabled) {
            this.enableEventBridgeNotification();
        }
    }
    static fromBucketArn(scope, id, bucketArn) {
        return Bucket.fromBucketAttributes(scope, id, { bucketArn });
    }
    static fromBucketName(scope, id, bucketName) {
        return Bucket.fromBucketAttributes(scope, id, { bucketName });
    }
    /**
     * Creates a Bucket construct that represents an external bucket.
     *
     * @param scope The parent creating construct (usually `this`).
     * @param id The construct's name.
     * @param attrs A `BucketAttributes` object. Can be obtained from a call to
     * `bucket.export()` or manually created.
     */
    static fromBucketAttributes(scope, id, attrs) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_BucketAttributes(attrs);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.fromBucketAttributes);
            }
            throw error;
        }
        const stack = core_1.Stack.of(scope);
        const region = attrs.region ?? stack.region;
        const urlSuffix = stack.urlSuffix;
        const bucketName = util_1.parseBucketName(scope, attrs);
        if (!bucketName) {
            throw new Error('Bucket name is required');
        }
        Bucket.validateBucketName(bucketName);
        const newUrlFormat = attrs.bucketWebsiteNewUrlFormat === undefined
            ? false
            : attrs.bucketWebsiteNewUrlFormat;
        const websiteDomain = newUrlFormat
            ? `${bucketName}.s3-website.${region}.${urlSuffix}`
            : `${bucketName}.s3-website-${region}.${urlSuffix}`;
        class Import extends BucketBase {
            constructor() {
                super(...arguments);
                this.bucketName = bucketName;
                this.bucketArn = util_1.parseBucketArn(scope, attrs);
                this.bucketDomainName = attrs.bucketDomainName || `${bucketName}.s3.${urlSuffix}`;
                this.bucketWebsiteUrl = attrs.bucketWebsiteUrl || `http://${websiteDomain}`;
                this.bucketWebsiteDomainName = attrs.bucketWebsiteUrl ? core_1.Fn.select(2, core_1.Fn.split('/', attrs.bucketWebsiteUrl)) : websiteDomain;
                this.bucketRegionalDomainName = attrs.bucketRegionalDomainName || `${bucketName}.s3.${region}.${urlSuffix}`;
                this.bucketDualStackDomainName = attrs.bucketDualStackDomainName || `${bucketName}.s3.dualstack.${region}.${urlSuffix}`;
                this.bucketWebsiteNewUrlFormat = newUrlFormat;
                this.encryptionKey = attrs.encryptionKey;
                this.isWebsite = attrs.isWebsite ?? false;
                this.policy = undefined;
                this.autoCreatePolicy = false;
                this.disallowPublicAccess = false;
                this.notificationsHandlerRole = attrs.notificationsHandlerRole;
            }
            /**
             * Exports this bucket from the stack.
             */
            export() {
                return attrs;
            }
        }
        return new Import(scope, id, {
            account: attrs.account,
            region: attrs.region,
        });
    }
    /**
     * Thrown an exception if the given bucket name is not valid.
     *
     * @param physicalName name of the bucket.
     */
    static validateBucketName(physicalName) {
        const bucketName = physicalName;
        if (!bucketName || core_1.Token.isUnresolved(bucketName)) {
            // the name is a late-bound value, not a defined string,
            // so skip validation
            return;
        }
        const errors = [];
        // Rules codified from https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
        if (bucketName.length < 3 || bucketName.length > 63) {
            errors.push('Bucket name must be at least 3 and no more than 63 characters');
        }
        const charsetMatch = bucketName.match(/[^a-z0-9.-]/);
        if (charsetMatch) {
            errors.push('Bucket name must only contain lowercase characters and the symbols, period (.) and dash (-) '
                + `(offset: ${charsetMatch.index})`);
        }
        if (!/[a-z0-9]/.test(bucketName.charAt(0))) {
            errors.push('Bucket name must start and end with a lowercase character or number '
                + '(offset: 0)');
        }
        if (!/[a-z0-9]/.test(bucketName.charAt(bucketName.length - 1))) {
            errors.push('Bucket name must start and end with a lowercase character or number '
                + `(offset: ${bucketName.length - 1})`);
        }
        const consecSymbolMatch = bucketName.match(/\.-|-\.|\.\./);
        if (consecSymbolMatch) {
            errors.push('Bucket name must not have dash next to period, or period next to dash, or consecutive periods '
                + `(offset: ${consecSymbolMatch.index})`);
        }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bucketName)) {
            errors.push('Bucket name must not resemble an IP address');
        }
        if (errors.length > 0) {
            throw new Error(`Invalid S3 bucket name (value: ${bucketName})${os_1.EOL}${errors.join(os_1.EOL)}`);
        }
    }
    /**
     * Add a lifecycle rule to the bucket
     *
     * @param rule The rule to add
     */
    addLifecycleRule(rule) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_LifecycleRule(rule);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addLifecycleRule);
            }
            throw error;
        }
        if ((rule.noncurrentVersionExpiration !== undefined
            || (rule.noncurrentVersionTransitions && rule.noncurrentVersionTransitions.length > 0))
            && !this.versioned) {
            throw new Error("Cannot use 'noncurrent' rules on a nonversioned bucket");
        }
        this.lifecycleRules.push(rule);
    }
    /**
     * Adds a metrics configuration for the CloudWatch request metrics from the bucket.
     *
     * @param metric The metric configuration to add
     */
    addMetric(metric) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_BucketMetrics(metric);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addMetric);
            }
            throw error;
        }
        this.metrics.push(metric);
    }
    /**
     * Adds a cross-origin access configuration for objects in an Amazon S3 bucket
     *
     * @param rule The CORS configuration rule to add
     */
    addCorsRule(rule) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_CorsRule(rule);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addCorsRule);
            }
            throw error;
        }
        this.cors.push(rule);
    }
    /**
     * Add an inventory configuration.
     *
     * @param inventory configuration to add
     */
    addInventory(inventory) {
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_Inventory(inventory);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, this.addInventory);
            }
            throw error;
        }
        this.inventories.push(inventory);
    }
    /**
     * Adds an iam statement to enforce SSL requests only.
     */
    enforceSSLStatement() {
        const statement = new iam.PolicyStatement({
            actions: ['s3:*'],
            conditions: {
                Bool: { 'aws:SecureTransport': 'false' },
            },
            effect: iam.Effect.DENY,
            resources: [
                this.bucketArn,
                this.arnForObjects('*'),
            ],
            principals: [new iam.AnyPrincipal()],
        });
        this.addToResourcePolicy(statement);
    }
    /**
     * Set up key properties and return the Bucket encryption property from the
     * user's configuration.
     */
    parseEncryption(props) {
        // default based on whether encryptionKey is specified
        let encryptionType = props.encryption;
        if (encryptionType === undefined) {
            encryptionType = props.encryptionKey ? BucketEncryption.KMS : BucketEncryption.UNENCRYPTED;
        }
        // if encryption key is set, encryption must be set to KMS.
        if (encryptionType !== BucketEncryption.KMS && props.encryptionKey) {
            throw new Error(`encryptionKey is specified, so 'encryption' must be set to KMS (value: ${encryptionType})`);
        }
        // if bucketKeyEnabled is set, encryption must be set to KMS.
        if (props.bucketKeyEnabled && encryptionType !== BucketEncryption.KMS) {
            throw new Error(`bucketKeyEnabled is specified, so 'encryption' must be set to KMS (value: ${encryptionType})`);
        }
        if (encryptionType === BucketEncryption.UNENCRYPTED) {
            return { bucketEncryption: undefined, encryptionKey: undefined };
        }
        if (encryptionType === BucketEncryption.KMS) {
            const encryptionKey = props.encryptionKey || new kms.Key(this, 'Key', {
                description: `Created by ${this.node.path}`,
            });
            const bucketEncryption = {
                serverSideEncryptionConfiguration: [
                    {
                        bucketKeyEnabled: props.bucketKeyEnabled,
                        serverSideEncryptionByDefault: {
                            sseAlgorithm: 'aws:kms',
                            kmsMasterKeyId: encryptionKey.keyArn,
                        },
                    },
                ],
            };
            return { encryptionKey, bucketEncryption };
        }
        if (encryptionType === BucketEncryption.S3_MANAGED) {
            const bucketEncryption = {
                serverSideEncryptionConfiguration: [
                    { serverSideEncryptionByDefault: { sseAlgorithm: 'AES256' } },
                ],
            };
            return { bucketEncryption };
        }
        if (encryptionType === BucketEncryption.KMS_MANAGED) {
            const bucketEncryption = {
                serverSideEncryptionConfiguration: [
                    { serverSideEncryptionByDefault: { sseAlgorithm: 'aws:kms' } },
                ],
            };
            return { bucketEncryption };
        }
        throw new Error(`Unexpected 'encryptionType': ${encryptionType}`);
    }
    /**
     * Parse the lifecycle configuration out of the bucket props
     * @param props Par
     */
    parseLifecycleConfiguration() {
        if (!this.lifecycleRules || this.lifecycleRules.length === 0) {
            return undefined;
        }
        const self = this;
        return { rules: this.lifecycleRules.map(parseLifecycleRule) };
        function parseLifecycleRule(rule) {
            const enabled = rule.enabled ?? true;
            const x = {
                // eslint-disable-next-line max-len
                abortIncompleteMultipartUpload: rule.abortIncompleteMultipartUploadAfter !== undefined ? { daysAfterInitiation: rule.abortIncompleteMultipartUploadAfter.toDays() } : undefined,
                expirationDate: rule.expirationDate,
                expirationInDays: rule.expiration?.toDays(),
                id: rule.id,
                noncurrentVersionExpiration: rule.noncurrentVersionExpiration && {
                    noncurrentDays: rule.noncurrentVersionExpiration.toDays(),
                    newerNoncurrentVersions: rule.noncurrentVersionsToRetain,
                },
                noncurrentVersionTransitions: mapOrUndefined(rule.noncurrentVersionTransitions, t => ({
                    storageClass: t.storageClass.value,
                    transitionInDays: t.transitionAfter.toDays(),
                    newerNoncurrentVersions: t.noncurrentVersionsToRetain,
                })),
                prefix: rule.prefix,
                status: enabled ? 'Enabled' : 'Disabled',
                transitions: mapOrUndefined(rule.transitions, t => ({
                    storageClass: t.storageClass.value,
                    transitionDate: t.transitionDate,
                    transitionInDays: t.transitionAfter && t.transitionAfter.toDays(),
                })),
                expiredObjectDeleteMarker: rule.expiredObjectDeleteMarker,
                tagFilters: self.parseTagFilters(rule.tagFilters),
                objectSizeLessThan: rule.objectSizeLessThan,
                objectSizeGreaterThan: rule.objectSizeGreaterThan,
            };
            return x;
        }
    }
    parseServerAccessLogs(props) {
        if (!props.serverAccessLogsBucket && !props.serverAccessLogsPrefix) {
            return undefined;
        }
        return {
            destinationBucketName: props.serverAccessLogsBucket?.bucketName,
            logFilePrefix: props.serverAccessLogsPrefix,
        };
    }
    parseMetricConfiguration() {
        if (!this.metrics || this.metrics.length === 0) {
            return undefined;
        }
        const self = this;
        return this.metrics.map(parseMetric);
        function parseMetric(metric) {
            return {
                id: metric.id,
                prefix: metric.prefix,
                tagFilters: self.parseTagFilters(metric.tagFilters),
            };
        }
    }
    parseCorsConfiguration() {
        if (!this.cors || this.cors.length === 0) {
            return undefined;
        }
        return { corsRules: this.cors.map(parseCors) };
        function parseCors(rule) {
            return {
                id: rule.id,
                maxAge: rule.maxAge,
                allowedHeaders: rule.allowedHeaders,
                allowedMethods: rule.allowedMethods,
                allowedOrigins: rule.allowedOrigins,
                exposedHeaders: rule.exposedHeaders,
            };
        }
    }
    parseTagFilters(tagFilters) {
        if (!tagFilters || tagFilters.length === 0) {
            return undefined;
        }
        return Object.keys(tagFilters).map(tag => ({
            key: tag,
            value: tagFilters[tag],
        }));
    }
    parseOwnershipControls({ objectOwnership }) {
        if (!objectOwnership) {
            return undefined;
        }
        return {
            rules: [{
                    objectOwnership,
                }],
        };
    }
    parseTieringConfig({ intelligentTieringConfigurations }) {
        if (!intelligentTieringConfigurations) {
            return undefined;
        }
        return intelligentTieringConfigurations.map(config => {
            const tierings = [];
            if (config.archiveAccessTierTime) {
                tierings.push({
                    accessTier: 'ARCHIVE_ACCESS',
                    days: config.archiveAccessTierTime.toDays({ integral: true }),
                });
            }
            if (config.deepArchiveAccessTierTime) {
                tierings.push({
                    accessTier: 'DEEP_ARCHIVE_ACCESS',
                    days: config.deepArchiveAccessTierTime.toDays({ integral: true }),
                });
            }
            return {
                id: config.name,
                prefix: config.prefix,
                status: 'Enabled',
                tagFilters: config.tags,
                tierings: tierings,
            };
        });
    }
    renderWebsiteConfiguration(props) {
        if (!props.websiteErrorDocument && !props.websiteIndexDocument && !props.websiteRedirect && !props.websiteRoutingRules) {
            return undefined;
        }
        if (props.websiteErrorDocument && !props.websiteIndexDocument) {
            throw new Error('"websiteIndexDocument" is required if "websiteErrorDocument" is set');
        }
        if (props.websiteRedirect && (props.websiteErrorDocument || props.websiteIndexDocument || props.websiteRoutingRules)) {
            throw new Error('"websiteIndexDocument", "websiteErrorDocument" and, "websiteRoutingRules" cannot be set if "websiteRedirect" is used');
        }
        const routingRules = props.websiteRoutingRules ? props.websiteRoutingRules.map((rule) => {
            if (rule.condition && !rule.condition.httpErrorCodeReturnedEquals && !rule.condition.keyPrefixEquals) {
                throw new Error('The condition property cannot be an empty object');
            }
            return {
                redirectRule: {
                    hostName: rule.hostName,
                    httpRedirectCode: rule.httpRedirectCode,
                    protocol: rule.protocol,
                    replaceKeyWith: rule.replaceKey && rule.replaceKey.withKey,
                    replaceKeyPrefixWith: rule.replaceKey && rule.replaceKey.prefixWithKey,
                },
                routingRuleCondition: rule.condition,
            };
        }) : undefined;
        return {
            indexDocument: props.websiteIndexDocument,
            errorDocument: props.websiteErrorDocument,
            redirectAllRequestsTo: props.websiteRedirect,
            routingRules,
        };
    }
    /**
     * Allows the LogDelivery group to write, fails if ACL was set differently.
     *
     * @see
     * https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
     */
    allowLogDelivery() {
        if (this.accessControl && this.accessControl !== BucketAccessControl.LOG_DELIVERY_WRITE) {
            throw new Error("Cannot enable log delivery to this bucket because the bucket's ACL has been set and can't be changed");
        }
        this.accessControl = BucketAccessControl.LOG_DELIVERY_WRITE;
    }
    parseInventoryConfiguration() {
        if (!this.inventories || this.inventories.length === 0) {
            return undefined;
        }
        return this.inventories.map((inventory, index) => {
            const format = inventory.format ?? InventoryFormat.CSV;
            const frequency = inventory.frequency ?? InventoryFrequency.WEEKLY;
            const id = inventory.inventoryId ?? `${this.node.id}Inventory${index}`;
            if (inventory.destination.bucket instanceof Bucket) {
                inventory.destination.bucket.addToResourcePolicy(new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: ['s3:PutObject'],
                    resources: [
                        inventory.destination.bucket.bucketArn,
                        inventory.destination.bucket.arnForObjects(`${inventory.destination.prefix ?? ''}*`),
                    ],
                    principals: [new iam.ServicePrincipal('s3.amazonaws.com')],
                    conditions: {
                        ArnLike: {
                            'aws:SourceArn': this.bucketArn,
                        },
                    },
                }));
            }
            return {
                id,
                destination: {
                    bucketArn: inventory.destination.bucket.bucketArn,
                    bucketAccountId: inventory.destination.bucketOwner,
                    prefix: inventory.destination.prefix,
                    format,
                },
                enabled: inventory.enabled ?? true,
                includedObjectVersions: inventory.includeObjectVersions ?? InventoryObjectVersion.ALL,
                scheduleFrequency: frequency,
                optionalFields: inventory.optionalFields,
                prefix: inventory.objectsPrefix,
            };
        });
    }
    enableAutoDeleteObjects() {
        const provider = core_1.CustomResourceProvider.getOrCreateProvider(this, AUTO_DELETE_OBJECTS_RESOURCE_TYPE, {
            codeDirectory: path.join(__dirname, 'auto-delete-objects-handler'),
            runtime: core_1.CustomResourceProviderRuntime.NODEJS_14_X,
            description: `Lambda function for auto-deleting objects in ${this.bucketName} S3 bucket.`,
        });
        // Use a bucket policy to allow the custom resource to delete
        // objects in the bucket
        this.addToResourcePolicy(new iam.PolicyStatement({
            actions: [
                // list objects
                ...perms.BUCKET_READ_METADATA_ACTIONS,
                ...perms.BUCKET_DELETE_ACTIONS,
            ],
            resources: [
                this.bucketArn,
                this.arnForObjects('*'),
            ],
            principals: [new iam.ArnPrincipal(provider.roleArn)],
        }));
        const customResource = new core_1.CustomResource(this, 'AutoDeleteObjectsCustomResource', {
            resourceType: AUTO_DELETE_OBJECTS_RESOURCE_TYPE,
            serviceToken: provider.serviceToken,
            properties: {
                BucketName: this.bucketName,
            },
        });
        // Ensure bucket policy is deleted AFTER the custom resource otherwise
        // we don't have permissions to list and delete in the bucket.
        // (add a `if` to make TS happy)
        if (this.policy) {
            customResource.node.addDependency(this.policy);
        }
        // We also tag the bucket to record the fact that we want it autodeleted.
        // The custom resource will check this tag before actually doing the delete.
        // Because tagging and untagging will ALWAYS happen before the CR is deleted,
        // we can set `autoDeleteObjects: false` without the removal of the CR emptying
        // the bucket as a side effect.
        core_1.Tags.of(this._resource).add(AUTO_DELETE_OBJECTS_TAG, 'true');
    }
}
exports.Bucket = Bucket;
_c = JSII_RTTI_SYMBOL_1;
Bucket[_c] = { fqn: "@aws-cdk/aws-s3.Bucket", version: "0.0.0" };
/**
 * What kind of server-side encryption to apply to this bucket
 */
var BucketEncryption;
(function (BucketEncryption) {
    /**
     * Objects in the bucket are not encrypted.
     */
    BucketEncryption["UNENCRYPTED"] = "NONE";
    /**
     * Server-side KMS encryption with a master key managed by KMS.
     */
    BucketEncryption["KMS_MANAGED"] = "MANAGED";
    /**
     * Server-side encryption with a master key managed by S3.
     */
    BucketEncryption["S3_MANAGED"] = "S3MANAGED";
    /**
     * Server-side encryption with a KMS key managed by the user.
     * If `encryptionKey` is specified, this key will be used, otherwise, one will be defined.
     */
    BucketEncryption["KMS"] = "KMS";
})(BucketEncryption = exports.BucketEncryption || (exports.BucketEncryption = {}));
/**
 * Notification event types.
 * @link https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html#supported-notification-event-types
 */
var EventType;
(function (EventType) {
    /**
     * Amazon S3 APIs such as PUT, POST, and COPY can create an object. Using
     * these event types, you can enable notification when an object is created
     * using a specific API, or you can use the s3:ObjectCreated:* event type to
     * request notification regardless of the API that was used to create an
     * object.
     */
    EventType["OBJECT_CREATED"] = "s3:ObjectCreated:*";
    /**
     * Amazon S3 APIs such as PUT, POST, and COPY can create an object. Using
     * these event types, you can enable notification when an object is created
     * using a specific API, or you can use the s3:ObjectCreated:* event type to
     * request notification regardless of the API that was used to create an
     * object.
     */
    EventType["OBJECT_CREATED_PUT"] = "s3:ObjectCreated:Put";
    /**
     * Amazon S3 APIs such as PUT, POST, and COPY can create an object. Using
     * these event types, you can enable notification when an object is created
     * using a specific API, or you can use the s3:ObjectCreated:* event type to
     * request notification regardless of the API that was used to create an
     * object.
     */
    EventType["OBJECT_CREATED_POST"] = "s3:ObjectCreated:Post";
    /**
     * Amazon S3 APIs such as PUT, POST, and COPY can create an object. Using
     * these event types, you can enable notification when an object is created
     * using a specific API, or you can use the s3:ObjectCreated:* event type to
     * request notification regardless of the API that was used to create an
     * object.
     */
    EventType["OBJECT_CREATED_COPY"] = "s3:ObjectCreated:Copy";
    /**
     * Amazon S3 APIs such as PUT, POST, and COPY can create an object. Using
     * these event types, you can enable notification when an object is created
     * using a specific API, or you can use the s3:ObjectCreated:* event type to
     * request notification regardless of the API that was used to create an
     * object.
     */
    EventType["OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD"] = "s3:ObjectCreated:CompleteMultipartUpload";
    /**
     * By using the ObjectRemoved event types, you can enable notification when
     * an object or a batch of objects is removed from a bucket.
     *
     * You can request notification when an object is deleted or a versioned
     * object is permanently deleted by using the s3:ObjectRemoved:Delete event
     * type. Or you can request notification when a delete marker is created for
     * a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
     * information about deleting versioned objects, see Deleting Object
     * Versions. You can also use a wildcard s3:ObjectRemoved:* to request
     * notification anytime an object is deleted.
     *
     * You will not receive event notifications from automatic deletes from
     * lifecycle policies or from failed operations.
     */
    EventType["OBJECT_REMOVED"] = "s3:ObjectRemoved:*";
    /**
     * By using the ObjectRemoved event types, you can enable notification when
     * an object or a batch of objects is removed from a bucket.
     *
     * You can request notification when an object is deleted or a versioned
     * object is permanently deleted by using the s3:ObjectRemoved:Delete event
     * type. Or you can request notification when a delete marker is created for
     * a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
     * information about deleting versioned objects, see Deleting Object
     * Versions. You can also use a wildcard s3:ObjectRemoved:* to request
     * notification anytime an object is deleted.
     *
     * You will not receive event notifications from automatic deletes from
     * lifecycle policies or from failed operations.
     */
    EventType["OBJECT_REMOVED_DELETE"] = "s3:ObjectRemoved:Delete";
    /**
     * By using the ObjectRemoved event types, you can enable notification when
     * an object or a batch of objects is removed from a bucket.
     *
     * You can request notification when an object is deleted or a versioned
     * object is permanently deleted by using the s3:ObjectRemoved:Delete event
     * type. Or you can request notification when a delete marker is created for
     * a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
     * information about deleting versioned objects, see Deleting Object
     * Versions. You can also use a wildcard s3:ObjectRemoved:* to request
     * notification anytime an object is deleted.
     *
     * You will not receive event notifications from automatic deletes from
     * lifecycle policies or from failed operations.
     */
    EventType["OBJECT_REMOVED_DELETE_MARKER_CREATED"] = "s3:ObjectRemoved:DeleteMarkerCreated";
    /**
     * Using restore object event types you can receive notifications for
     * initiation and completion when restoring objects from the S3 Glacier
     * storage class.
     *
     * You use s3:ObjectRestore:Post to request notification of object restoration
     * initiation.
     */
    EventType["OBJECT_RESTORE_POST"] = "s3:ObjectRestore:Post";
    /**
     * Using restore object event types you can receive notifications for
     * initiation and completion when restoring objects from the S3 Glacier
     * storage class.
     *
     * You use s3:ObjectRestore:Completed to request notification of
     * restoration completion.
     */
    EventType["OBJECT_RESTORE_COMPLETED"] = "s3:ObjectRestore:Completed";
    /**
     * Using restore object event types you can receive notifications for
     * initiation and completion when restoring objects from the S3 Glacier
     * storage class.
     *
     * You use s3:ObjectRestore:Delete to request notification of
     * restoration completion.
     */
    EventType["OBJECT_RESTORE_DELETE"] = "s3:ObjectRestore:Delete";
    /**
     * You can use this event type to request Amazon S3 to send a notification
     * message when Amazon S3 detects that an object of the RRS storage class is
     * lost.
     */
    EventType["REDUCED_REDUNDANCY_LOST_OBJECT"] = "s3:ReducedRedundancyLostObject";
    /**
     * You receive this notification event when an object that was eligible for
     * replication using Amazon S3 Replication Time Control failed to replicate.
     */
    EventType["REPLICATION_OPERATION_FAILED_REPLICATION"] = "s3:Replication:OperationFailedReplication";
    /**
     * You receive this notification event when an object that was eligible for
     * replication using Amazon S3 Replication Time Control exceeded the 15-minute
     * threshold for replication.
     */
    EventType["REPLICATION_OPERATION_MISSED_THRESHOLD"] = "s3:Replication:OperationMissedThreshold";
    /**
     * You receive this notification event for an object that was eligible for
     * replication using the Amazon S3 Replication Time Control feature replicated
     * after the 15-minute threshold.
     */
    EventType["REPLICATION_OPERATION_REPLICATED_AFTER_THRESHOLD"] = "s3:Replication:OperationReplicatedAfterThreshold";
    /**
     * You receive this notification event for an object that was eligible for
     * replication using Amazon S3 Replication Time Control but is no longer tracked
     * by replication metrics.
     */
    EventType["REPLICATION_OPERATION_NOT_TRACKED"] = "s3:Replication:OperationNotTracked";
    /**
     * By using the LifecycleExpiration event types, you can receive a notification
     * when Amazon S3 deletes an object based on your S3 Lifecycle configuration.
     */
    EventType["LIFECYCLE_EXPIRATION"] = "s3:LifecycleExpiration:*";
    /**
     * The s3:LifecycleExpiration:Delete event type notifies you when an object
     * in an unversioned bucket is deleted.
     * It also notifies you when an object version is permanently deleted by an
     * S3 Lifecycle configuration.
     */
    EventType["LIFECYCLE_EXPIRATION_DELETE"] = "s3:LifecycleExpiration:Delete";
    /**
     * The s3:LifecycleExpiration:DeleteMarkerCreated event type notifies you
     * when S3 Lifecycle creates a delete marker when a current version of an
     * object in versioned bucket is deleted.
     */
    EventType["LIFECYCLE_EXPIRATION_DELETE_MARKER_CREATED"] = "s3:LifecycleExpiration:DeleteMarkerCreated";
    /**
     * You receive this notification event when an object is transitioned to
     * another Amazon S3 storage class by an S3 Lifecycle configuration.
     */
    EventType["LIFECYCLE_TRANSITION"] = "s3:LifecycleTransition";
    /**
     * You receive this notification event when an object within the
     * S3 Intelligent-Tiering storage class moved to the Archive Access tier or
     * Deep Archive Access tier.
     */
    EventType["INTELLIGENT_TIERING"] = "s3:IntelligentTiering";
    /**
     * By using the ObjectTagging event types, you can enable notification when
     * an object tag is added or deleted from an object.
     */
    EventType["OBJECT_TAGGING"] = "s3:ObjectTagging:*";
    /**
     * The s3:ObjectTagging:Put event type notifies you when a tag is PUT on an
     * object or an existing tag is updated.
  
     */
    EventType["OBJECT_TAGGING_PUT"] = "s3:ObjectTagging:Put";
    /**
     * The s3:ObjectTagging:Delete event type notifies you when a tag is removed
     * from an object.
     */
    EventType["OBJECT_TAGGING_DELETE"] = "s3:ObjectTagging:Delete";
    /**
     * You receive this notification event when an ACL is PUT on an object or when
     * an existing ACL is changed.
     * An event is not generated when a request results in no change to an
     * object’s ACL.
     */
    EventType["OBJECT_ACL_PUT"] = "s3:ObjectAcl:Put";
})(EventType = exports.EventType || (exports.EventType = {}));
/**
 * Default bucket access control types.
 *
 * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html
 */
var BucketAccessControl;
(function (BucketAccessControl) {
    /**
     * Owner gets FULL_CONTROL. No one else has access rights.
     */
    BucketAccessControl["PRIVATE"] = "Private";
    /**
     * Owner gets FULL_CONTROL. The AllUsers group gets READ access.
     */
    BucketAccessControl["PUBLIC_READ"] = "PublicRead";
    /**
     * Owner gets FULL_CONTROL. The AllUsers group gets READ and WRITE access.
     * Granting this on a bucket is generally not recommended.
     */
    BucketAccessControl["PUBLIC_READ_WRITE"] = "PublicReadWrite";
    /**
     * Owner gets FULL_CONTROL. The AuthenticatedUsers group gets READ access.
     */
    BucketAccessControl["AUTHENTICATED_READ"] = "AuthenticatedRead";
    /**
     * The LogDelivery group gets WRITE and READ_ACP permissions on the bucket.
     * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html
     */
    BucketAccessControl["LOG_DELIVERY_WRITE"] = "LogDeliveryWrite";
    /**
     * Object owner gets FULL_CONTROL. Bucket owner gets READ access.
     * If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
     */
    BucketAccessControl["BUCKET_OWNER_READ"] = "BucketOwnerRead";
    /**
     * Both the object owner and the bucket owner get FULL_CONTROL over the object.
     * If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
     */
    BucketAccessControl["BUCKET_OWNER_FULL_CONTROL"] = "BucketOwnerFullControl";
    /**
     * Owner gets FULL_CONTROL. Amazon EC2 gets READ access to GET an Amazon Machine Image (AMI) bundle from Amazon S3.
     */
    BucketAccessControl["AWS_EXEC_READ"] = "AwsExecRead";
})(BucketAccessControl = exports.BucketAccessControl || (exports.BucketAccessControl = {}));
class ReplaceKey {
    constructor(withKey, prefixWithKey) {
        this.withKey = withKey;
        this.prefixWithKey = prefixWithKey;
    }
    /**
     * The specific object key to use in the redirect request
     */
    static with(keyReplacement) {
        return new this(keyReplacement);
    }
    /**
     * The object key prefix to use in the redirect request
     */
    static prefixWith(keyReplacement) {
        return new this(undefined, keyReplacement);
    }
}
exports.ReplaceKey = ReplaceKey;
_d = JSII_RTTI_SYMBOL_1;
ReplaceKey[_d] = { fqn: "@aws-cdk/aws-s3.ReplaceKey", version: "0.0.0" };
function mapOrUndefined(list, callback) {
    if (!list || list.length === 0) {
        return undefined;
    }
    return list.map(callback);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVja2V0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiYnVja2V0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLDJCQUF5QjtBQUN6Qiw2QkFBNkI7QUFDN0IsOENBQThDO0FBQzlDLHdDQUF3QztBQUN4Qyx3Q0FBd0M7QUFDeEMsd0NBZXVCO0FBQ3ZCLHlDQUF5QztBQUV6QyxtREFBK0M7QUFFL0MscUVBQStEO0FBQy9ELGlDQUFpQztBQUVqQyxpREFBMkM7QUFDM0MsaUNBQXlEO0FBRXpELE1BQU0saUNBQWlDLEdBQUcsNkJBQTZCLENBQUM7QUFDeEUsTUFBTSx1QkFBdUIsR0FBRyw2QkFBNkIsQ0FBQztBQW1iOUQ7Ozs7Ozs7Ozs7Ozs7Ozs7R0FnQkc7QUFDSCxNQUFzQixVQUFXLFNBQVEsZUFBUTtJQTBDL0MsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUF1QixFQUFFO1FBQ2pFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLElBQUksQ0FBQyxJQUFJLENBQUMsYUFBYSxDQUFDLEVBQUUsUUFBUSxFQUFFLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsUUFBUSxDQUFDLHlCQUF5QixFQUFFLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQztLQUN0RztJQUVEOzs7Ozs7OztPQVFHO0lBQ0ksaUJBQWlCLENBQUMsRUFBVSxFQUFFLFVBQTBDLEVBQUU7Ozs7Ozs7Ozs7UUFDL0UsTUFBTSxJQUFJLEdBQUcsSUFBSSxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsT0FBTyxDQUFDLENBQUM7UUFDaEQsSUFBSSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDL0IsSUFBSSxDQUFDLGVBQWUsQ0FBQztZQUNuQixNQUFNLEVBQUUsQ0FBQyxRQUFRLENBQUM7WUFDbEIsVUFBVSxFQUFFLENBQUMsNkJBQTZCLENBQUM7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QVAsT0FBTyxDQUFTO1FBQWtCLGtCQUFhLEdBQWIsYUFBYSxDQUFTO0tBQzNGO0lBZkQ7O09BRUc7SUFDSSxNQUFNLENBQUMsSUFBSSxDQUFDLGNBQXNCO1FBQ3ZDLE9BQU8sSUFBSSxJQUFJLENBQUMsY0FBYyxDQUFDLENBQUM7S0FDakM7SUFFRDs7T0FFRztJQUNJLE1BQU0sQ0FBQyxVQUFVLENBQUMsY0FBc0I7UUFDN0MsT0FBTyxJQUFJLElBQUksQ0FBQyxTQUFTLEVBQUUsY0FBYyxDQUFDLENBQUM7S0FDNUM7O0FBYkgsZ0NBaUJDOzs7QUFvRUQsU0FBUyxjQUFjLENBQU8sSUFBcUIsRUFBRSxRQUEyQjtJQUM5RSxJQUFJLENBQUMsSUFBSSxJQUFJLElBQUksQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO1FBQzlCLE9BQU8sU0FBUyxDQUFDO0tBQ2xCO0lBRUQsT0FBTyxJQUFJLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQzVCLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBFT0wgfSBmcm9tICdvcyc7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0ICogYXMgZXZlbnRzIGZyb20gJ0Bhd3MtY2RrL2F3cy1ldmVudHMnO1xuaW1wb3J0ICogYXMgaWFtIGZyb20gJ0Bhd3MtY2RrL2F3cy1pYW0nO1xuaW1wb3J0ICogYXMga21zIGZyb20gJ0Bhd3MtY2RrL2F3cy1rbXMnO1xuaW1wb3J0IHtcbiAgQ3VzdG9tUmVzb3VyY2UsXG4gIEN1c3RvbVJlc291cmNlUHJvdmlkZXIsXG4gIEN1c3RvbVJlc291cmNlUHJvdmlkZXJSdW50aW1lLFxuICBEdXJhdGlvbixcbiAgRmVhdHVyZUZsYWdzLFxuICBGbixcbiAgSVJlc291cmNlLFxuICBMYXp5LFxuICBSZW1vdmFsUG9saWN5LFxuICBSZXNvdXJjZSxcbiAgUmVzb3VyY2VQcm9wcyxcbiAgU3RhY2ssXG4gIFRhZ3MsXG4gIFRva2VuLFxufSBmcm9tICdAYXdzLWNkay9jb3JlJztcbmltcG9ydCAqIGFzIGN4YXBpIGZyb20gJ0Bhd3MtY2RrL2N4LWFwaSc7XG5pbXBvcnQgeyBDb25zdHJ1Y3QgfSBmcm9tICdjb25zdHJ1Y3RzJztcbmltcG9ydCB7IEJ1Y2tldFBvbGljeSB9IGZyb20gJy4vYnVja2V0LXBvbGljeSc7XG5pbXBvcnQgeyBJQnVja2V0Tm90aWZpY2F0aW9uRGVzdGluYXRpb24gfSBmcm9tICcuL2Rlc3RpbmF0aW9uJztcbmltcG9ydCB7IEJ1Y2tldE5vdGlmaWNhdGlvbnMgfSBmcm9tICcuL25vdGlmaWNhdGlvbnMtcmVzb3VyY2UnO1xuaW1wb3J0ICogYXMgcGVybXMgZnJvbSAnLi9wZXJtcyc7XG5pbXBvcnQgeyBMaWZlY3ljbGVSdWxlIH0gZnJvbSAnLi9ydWxlJztcbmltcG9ydCB7IENmbkJ1Y2tldCB9IGZyb20gJy4vczMuZ2VuZXJhdGVkJztcbmltcG9ydCB7IHBhcnNlQnVja2V0QXJuLCBwYXJzZUJ1Y2tldE5hbWUgfSBmcm9tICcuL3V0aWwnO1xuXG5jb25zdCBBVVRPX0RFTEVURV9PQkpFQ1RTX1JFU09VUkNFX1RZUEUgPSAnQ3VzdG9tOjpTM0F1dG9EZWxldGVPYmplY3RzJztcbmNvbnN0IEFVVE9fREVMRVRFX09CSkVDVFNfVEFHID0gJ2F3cy1jZGs6YXV0by1kZWxldGUtb2JqZWN0cyc7XG5cbmV4cG9ydCBpbnRlcmZhY2UgSUJ1Y2tldCBleHRlbmRzIElSZXNvdXJjZSB7XG4gIC8qKlxuICAgKiBUaGUgQVJOIG9mIHRoZSBidWNrZXQuXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldEFybjogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgbmFtZSBvZiB0aGUgYnVja2V0LlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBidWNrZXROYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBVUkwgb2YgdGhlIHN0YXRpYyB3ZWJzaXRlLlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBidWNrZXRXZWJzaXRlVXJsOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBEb21haW4gbmFtZSBvZiB0aGUgc3RhdGljIHdlYnNpdGUuXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldFdlYnNpdGVEb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBJUHY0IEROUyBuYW1lIG9mIHRoZSBzcGVjaWZpZWQgYnVja2V0LlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBidWNrZXREb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBJUHY2IEROUyBuYW1lIG9mIHRoZSBzcGVjaWZpZWQgYnVja2V0LlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBidWNrZXREdWFsU3RhY2tEb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSByZWdpb25hbCBkb21haW4gbmFtZSBvZiB0aGUgc3BlY2lmaWVkIGJ1Y2tldC5cbiAgICogQGF0dHJpYnV0ZVxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0UmVnaW9uYWxEb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIElmIHRoaXMgYnVja2V0IGhhcyBiZWVuIGNvbmZpZ3VyZWQgZm9yIHN0YXRpYyB3ZWJzaXRlIGhvc3RpbmcuXG4gICAqL1xuICByZWFkb25seSBpc1dlYnNpdGU/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBPcHRpb25hbCBLTVMgZW5jcnlwdGlvbiBrZXkgYXNzb2NpYXRlZCB3aXRoIHRoaXMgYnVja2V0LlxuICAgKi9cbiAgcmVhZG9ubHkgZW5jcnlwdGlvbktleT86IGttcy5JS2V5O1xuXG4gIC8qKlxuICAgKiBUaGUgcmVzb3VyY2UgcG9saWN5IGFzc29jaWF0ZWQgd2l0aCB0aGlzIGJ1Y2tldC5cbiAgICpcbiAgICogSWYgYGF1dG9DcmVhdGVQb2xpY3lgIGlzIHRydWUsIGEgYEJ1Y2tldFBvbGljeWAgd2lsbCBiZSBjcmVhdGVkIHVwb24gdGhlXG4gICAqIGZpcnN0IGNhbGwgdG8gYWRkVG9SZXNvdXJjZVBvbGljeShzKS5cbiAgICovXG4gIHBvbGljeT86IEJ1Y2tldFBvbGljeTtcblxuICAvKipcbiAgICogQWRkcyBhIHN0YXRlbWVudCB0byB0aGUgcmVzb3VyY2UgcG9saWN5IGZvciBhIHByaW5jaXBhbCAoaS5lLlxuICAgKiBhY2NvdW50L3JvbGUvc2VydmljZSkgdG8gcGVyZm9ybSBhY3Rpb25zIG9uIHRoaXMgYnVja2V0IGFuZC9vciBpdHNcbiAgICogY29udGVudHMuIFVzZSBgYnVja2V0QXJuYCBhbmQgYGFybkZvck9iamVjdHMoa2V5cylgIHRvIG9idGFpbiBBUk5zIGZvclxuICAgKiB0aGlzIGJ1Y2tldCBvciBvYmplY3RzLlxuICAgKlxuICAgKiBOb3RlIHRoYXQgdGhlIHBvbGljeSBzdGF0ZW1lbnQgbWF5IG9yIG1heSBub3QgYmUgYWRkZWQgdG8gdGhlIHBvbGljeS5cbiAgICogRm9yIGV4YW1wbGUsIHdoZW4gYW4gYElCdWNrZXRgIGlzIGNyZWF0ZWQgZnJvbSBhbiBleGlzdGluZyBidWNrZXQsXG4gICAqIGl0J3Mgbm90IHBvc3NpYmxlIHRvIHRlbGwgd2hldGhlciB0aGUgYnVja2V0IGFscmVhZHkgaGFzIGEgcG9saWN5XG4gICAqIGF0dGFjaGVkLCBsZXQgYWxvbmUgdG8gcmUtdXNlIHRoYXQgcG9saWN5IHRvIGFkZCBtb3JlIHN0YXRlbWVudHMgdG8gaXQuXG4gICAqIFNvIGl0J3Mgc2FmZXN0IHRvIGRvIG5vdGhpbmcgaW4gdGhlc2UgY2FzZXMuXG4gICAqXG4gICAqIEBwYXJhbSBwZXJtaXNzaW9uIHRoZSBwb2xpY3kgc3RhdGVtZW50IHRvIGJlIGFkZGVkIHRvIHRoZSBidWNrZXQnc1xuICAgKiBwb2xpY3kuXG4gICAqIEByZXR1cm5zIG1ldGFkYXRhIGFib3V0IHRoZSBleGVjdXRpb24gb2YgdGhpcyBtZXRob2QuIElmIHRoZSBwb2xpY3lcbiAgICogd2FzIG5vdCBhZGRlZCwgdGhlIHZhbHVlIG9mIGBzdGF0ZW1lbnRBZGRlZGAgd2lsbCBiZSBgZmFsc2VgLiBZb3VcbiAgICogc2hvdWxkIGFsd2F5cyBjaGVjayB0aGlzIHZhbHVlIHRvIG1ha2Ugc3VyZSB0aGF0IHRoZSBvcGVyYXRpb24gd2FzXG4gICAqIGFjdHVhbGx5IGNhcnJpZWQgb3V0LiBPdGhlcndpc2UsIHN5bnRoZXNpcyBhbmQgZGVwbG95IHdpbGwgdGVybWluYXRlXG4gICAqIHNpbGVudGx5LCB3aGljaCBtYXkgYmUgY29uZnVzaW5nLlxuICAgKi9cbiAgYWRkVG9SZXNvdXJjZVBvbGljeShwZXJtaXNzaW9uOiBpYW0uUG9saWN5U3RhdGVtZW50KTogaWFtLkFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHQ7XG5cbiAgLyoqXG4gICAqIFRoZSBodHRwcyBVUkwgb2YgYW4gUzMgb2JqZWN0LiBGb3IgZXhhbXBsZTpcbiAgICpcbiAgICogLSBgaHR0cHM6Ly9zMy51cy13ZXN0LTEuYW1hem9uYXdzLmNvbS9vbmx5YnVja2V0YFxuICAgKiAtIGBodHRwczovL3MzLnVzLXdlc3QtMS5hbWF6b25hd3MuY29tL2J1Y2tldC9rZXlgXG4gICAqIC0gYGh0dHBzOi8vczMuY24tbm9ydGgtMS5hbWF6b25hd3MuY29tLmNuL2NoaW5hLWJ1Y2tldC9teWtleWBcbiAgICogQHBhcmFtIGtleSBUaGUgUzMga2V5IG9mIHRoZSBvYmplY3QuIElmIG5vdCBzcGVjaWZpZWQsIHRoZSBVUkwgb2YgdGhlXG4gICAqICAgICAgYnVja2V0IGlzIHJldHVybmVkLlxuICAgKiBAcmV0dXJucyBhbiBPYmplY3RTM1VybCB0b2tlblxuICAgKi9cbiAgdXJsRm9yT2JqZWN0KGtleT86IHN0cmluZyk6IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIGh0dHBzIFRyYW5zZmVyIEFjY2VsZXJhdGlvbiBVUkwgb2YgYW4gUzMgb2JqZWN0LiBTcGVjaWZ5IGBkdWFsU3RhY2s6IHRydWVgIGF0IHRoZSBvcHRpb25zXG4gICAqIGZvciBkdWFsLXN0YWNrIGVuZHBvaW50IChjb25uZWN0IHRvIHRoZSBidWNrZXQgb3ZlciBJUHY2KS4gRm9yIGV4YW1wbGU6XG4gICAqXG4gICAqIC0gYGh0dHBzOi8vYnVja2V0LnMzLWFjY2VsZXJhdGUuYW1hem9uYXdzLmNvbWBcbiAgICogLSBgaHR0cHM6Ly9idWNrZXQuczMtYWNjZWxlcmF0ZS5hbWF6b25hd3MuY29tL2tleWBcbiAgICpcbiAgICogQHBhcmFtIGtleSBUaGUgUzMga2V5IG9mIHRoZSBvYmplY3QuIElmIG5vdCBzcGVjaWZpZWQsIHRoZSBVUkwgb2YgdGhlXG4gICAqICAgICAgYnVja2V0IGlzIHJldHVybmVkLlxuICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25zIGZvciBnZW5lcmF0aW5nIFVSTC5cbiAgICogQHJldHVybnMgYW4gVHJhbnNmZXJBY2NlbGVyYXRpb25VcmwgdG9rZW5cbiAgICovXG4gIHRyYW5zZmVyQWNjZWxlcmF0aW9uVXJsRm9yT2JqZWN0KGtleT86IHN0cmluZywgb3B0aW9ucz86IFRyYW5zZmVyQWNjZWxlcmF0aW9uVXJsT3B0aW9ucyk6IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHZpcnR1YWwgaG9zdGVkLXN0eWxlIFVSTCBvZiBhbiBTMyBvYmplY3QuIFNwZWNpZnkgYHJlZ2lvbmFsOiBmYWxzZWAgYXRcbiAgICogdGhlIG9wdGlvbnMgZm9yIG5vbi1yZWdpb25hbCBVUkwuIEZvciBleGFtcGxlOlxuICAgKlxuICAgKiAtIGBodHRwczovL29ubHktYnVja2V0LnMzLnVzLXdlc3QtMS5hbWF6b25hd3MuY29tYFxuICAgKiAtIGBodHRwczovL2J1Y2tldC5zMy51cy13ZXN0LTEuYW1hem9uYXdzLmNvbS9rZXlgXG4gICAqIC0gYGh0dHBzOi8vYnVja2V0LnMzLmFtYXpvbmF3cy5jb20va2V5YFxuICAgKiAtIGBodHRwczovL2NoaW5hLWJ1Y2tldC5zMy5jbi1ub3J0aC0xLmFtYXpvbmF3cy5jb20uY24vbXlrZXlgXG4gICAqIEBwYXJhbSBrZXkgVGhlIFMzIGtleSBvZiB0aGUgb2JqZWN0LiBJZiBub3Qgc3BlY2lmaWVkLCB0aGUgVVJMIG9mIHRoZVxuICAgKiAgICAgIGJ1Y2tldCBpcyByZXR1cm5lZC5cbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9ucyBmb3IgZ2VuZXJhdGluZyBVUkwuXG4gICAqIEByZXR1cm5zIGFuIE9iamVjdFMzVXJsIHRva2VuXG4gICAqL1xuICB2aXJ0dWFsSG9zdGVkVXJsRm9yT2JqZWN0KGtleT86IHN0cmluZywgb3B0aW9ucz86IFZpcnR1YWxIb3N0ZWRTdHlsZVVybE9wdGlvbnMpOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBTMyBVUkwgb2YgYW4gUzMgb2JqZWN0LiBGb3IgZXhhbXBsZTpcbiAgICogLSBgczM6Ly9vbmx5YnVja2V0YFxuICAgKiAtIGBzMzovL2J1Y2tldC9rZXlgXG4gICAqIEBwYXJhbSBrZXkgVGhlIFMzIGtleSBvZiB0aGUgb2JqZWN0LiBJZiBub3Qgc3BlY2lmaWVkLCB0aGUgUzMgVVJMIG9mIHRoZVxuICAgKiAgICAgIGJ1Y2tldCBpcyByZXR1cm5lZC5cbiAgICogQHJldHVybnMgYW4gT2JqZWN0UzNVcmwgdG9rZW5cbiAgICovXG4gIHMzVXJsRm9yT2JqZWN0KGtleT86IHN0cmluZyk6IHN0cmluZztcblxuICAvKipcbiAgICogUmV0dXJucyBhbiBBUk4gdGhhdCByZXByZXNlbnRzIGFsbCBvYmplY3RzIHdpdGhpbiB0aGUgYnVja2V0IHRoYXQgbWF0Y2hcbiAgICogdGhlIGtleSBwYXR0ZXJuIHNwZWNpZmllZC4gVG8gcmVwcmVzZW50IGFsbCBrZXlzLCBzcGVjaWZ5IGBgXCIqXCJgYC5cbiAgICovXG4gIGFybkZvck9iamVjdHMoa2V5UGF0dGVybjogc3RyaW5nKTogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBHcmFudCByZWFkIHBlcm1pc3Npb25zIGZvciB0aGlzIGJ1Y2tldCBhbmQgaXQncyBjb250ZW50cyB0byBhbiBJQU1cbiAgICogcHJpbmNpcGFsIChSb2xlL0dyb3VwL1VzZXIpLlxuICAgKlxuICAgKiBJZiBlbmNyeXB0aW9uIGlzIHVzZWQsIHBlcm1pc3Npb24gdG8gdXNlIHRoZSBrZXkgdG8gZGVjcnlwdCB0aGUgY29udGVudHNcbiAgICogb2YgdGhlIGJ1Y2tldCB3aWxsIGFsc28gYmUgZ3JhbnRlZCB0byB0aGUgc2FtZSBwcmluY2lwYWwuXG4gICAqXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgZ3JhbnRSZWFkKGlkZW50aXR5OiBpYW0uSUdyYW50YWJsZSwgb2JqZWN0c0tleVBhdHRlcm4/OiBhbnkpOiBpYW0uR3JhbnQ7XG5cbiAgLyoqXG4gICAqIEdyYW50IHdyaXRlIHBlcm1pc3Npb25zIHRvIHRoaXMgYnVja2V0IHRvIGFuIElBTSBwcmluY2lwYWwuXG4gICAqXG4gICAqIElmIGVuY3J5cHRpb24gaXMgdXNlZCwgcGVybWlzc2lvbiB0byB1c2UgdGhlIGtleSB0byBlbmNyeXB0IHRoZSBjb250ZW50c1xuICAgKiBvZiB3cml0dGVuIGZpbGVzIHdpbGwgYWxzbyBiZSBncmFudGVkIHRvIHRoZSBzYW1lIHByaW5jaXBhbC5cbiAgICpcbiAgICogQmVmb3JlIENESyB2ZXJzaW9uIDEuODUuMCwgdGhpcyBtZXRob2QgZ3JhbnRlZCB0aGUgYHMzOlB1dE9iamVjdCpgIHBlcm1pc3Npb24gdGhhdCBpbmNsdWRlZCBgczM6UHV0T2JqZWN0QWNsYCxcbiAgICogd2hpY2ggY291bGQgYmUgdXNlZCB0byBncmFudCByZWFkL3dyaXRlIG9iamVjdCBhY2Nlc3MgdG8gSUFNIHByaW5jaXBhbHMgaW4gb3RoZXIgYWNjb3VudHMuXG4gICAqIElmIHlvdSB3YW50IHRvIGdldCByaWQgb2YgdGhhdCBiZWhhdmlvciwgdXBkYXRlIHlvdXIgQ0RLIHZlcnNpb24gdG8gMS44NS4wIG9yIGxhdGVyLFxuICAgKiBhbmQgbWFrZSBzdXJlIHRoZSBgQGF3cy1jZGsvYXdzLXMzOmdyYW50V3JpdGVXaXRob3V0QWNsYCBmZWF0dXJlIGZsYWcgaXMgc2V0IHRvIGB0cnVlYFxuICAgKiBpbiB0aGUgYGNvbnRleHRgIGtleSBvZiB5b3VyIGNkay5qc29uIGZpbGUuXG4gICAqIElmIHlvdSd2ZSBhbHJlYWR5IHVwZGF0ZWQsIGJ1dCBzdGlsbCBuZWVkIHRoZSBwcmluY2lwYWwgdG8gaGF2ZSBwZXJtaXNzaW9ucyB0byBtb2RpZnkgdGhlIEFDTHMsXG4gICAqIHVzZSB0aGUge0BsaW5rIGdyYW50UHV0QWNsfSBtZXRob2QuXG4gICAqXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgZ3JhbnRXcml0ZShpZGVudGl0eTogaWFtLklHcmFudGFibGUsIG9iamVjdHNLZXlQYXR0ZXJuPzogYW55KTogaWFtLkdyYW50O1xuXG4gIC8qKlxuICAgKiBHcmFudHMgczM6UHV0T2JqZWN0KiBhbmQgczM6QWJvcnQqIHBlcm1pc3Npb25zIGZvciB0aGlzIGJ1Y2tldCB0byBhbiBJQU0gcHJpbmNpcGFsLlxuICAgKlxuICAgKiBJZiBlbmNyeXB0aW9uIGlzIHVzZWQsIHBlcm1pc3Npb24gdG8gdXNlIHRoZSBrZXkgdG8gZW5jcnlwdCB0aGUgY29udGVudHNcbiAgICogb2Ygd3JpdHRlbiBmaWxlcyB3aWxsIGFsc28gYmUgZ3JhbnRlZCB0byB0aGUgc2FtZSBwcmluY2lwYWwuXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgZ3JhbnRQdXQoaWRlbnRpdHk6IGlhbS5JR3JhbnRhYmxlLCBvYmplY3RzS2V5UGF0dGVybj86IGFueSk6IGlhbS5HcmFudDtcblxuICAvKipcbiAgICogR3JhbnQgdGhlIGdpdmVuIElBTSBpZGVudGl0eSBwZXJtaXNzaW9ucyB0byBtb2RpZnkgdGhlIEFDTHMgb2Ygb2JqZWN0cyBpbiB0aGUgZ2l2ZW4gQnVja2V0LlxuICAgKlxuICAgKiBJZiB5b3VyIGFwcGxpY2F0aW9uIGhhcyB0aGUgJ0Bhd3MtY2RrL2F3cy1zMzpncmFudFdyaXRlV2l0aG91dEFjbCcgZmVhdHVyZSBmbGFnIHNldCxcbiAgICogY2FsbGluZyB7QGxpbmsgZ3JhbnRXcml0ZX0gb3Ige0BsaW5rIGdyYW50UmVhZFdyaXRlfSBubyBsb25nZXIgZ3JhbnRzIHBlcm1pc3Npb25zIHRvIG1vZGlmeSB0aGUgQUNMcyBvZiB0aGUgb2JqZWN0cztcbiAgICogaW4gdGhpcyBjYXNlLCBpZiB5b3UgbmVlZCB0byBtb2RpZnkgb2JqZWN0IEFDTHMsIGNhbGwgdGhpcyBtZXRob2QgZXhwbGljaXRseS5cbiAgICpcbiAgICogQHBhcmFtIGlkZW50aXR5IFRoZSBwcmluY2lwYWxcbiAgICogQHBhcmFtIG9iamVjdHNLZXlQYXR0ZXJuIFJlc3RyaWN0IHRoZSBwZXJtaXNzaW9uIHRvIGEgY2VydGFpbiBrZXkgcGF0dGVybiAoZGVmYXVsdCAnKicpXG4gICAqL1xuICBncmFudFB1dEFjbChpZGVudGl0eTogaWFtLklHcmFudGFibGUsIG9iamVjdHNLZXlQYXR0ZXJuPzogc3RyaW5nKTogaWFtLkdyYW50O1xuXG4gIC8qKlxuICAgKiBHcmFudHMgczM6RGVsZXRlT2JqZWN0KiBwZXJtaXNzaW9uIHRvIGFuIElBTSBwcmluY2lwYWwgZm9yIG9iamVjdHNcbiAgICogaW4gdGhpcyBidWNrZXQuXG4gICAqXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgZ3JhbnREZWxldGUoaWRlbnRpdHk6IGlhbS5JR3JhbnRhYmxlLCBvYmplY3RzS2V5UGF0dGVybj86IGFueSk6IGlhbS5HcmFudDtcblxuICAvKipcbiAgICogR3JhbnRzIHJlYWQvd3JpdGUgcGVybWlzc2lvbnMgZm9yIHRoaXMgYnVja2V0IGFuZCBpdCdzIGNvbnRlbnRzIHRvIGFuIElBTVxuICAgKiBwcmluY2lwYWwgKFJvbGUvR3JvdXAvVXNlcikuXG4gICAqXG4gICAqIElmIGFuIGVuY3J5cHRpb24ga2V5IGlzIHVzZWQsIHBlcm1pc3Npb24gdG8gdXNlIHRoZSBrZXkgZm9yXG4gICAqIGVuY3J5cHQvZGVjcnlwdCB3aWxsIGFsc28gYmUgZ3JhbnRlZC5cbiAgICpcbiAgICogQmVmb3JlIENESyB2ZXJzaW9uIDEuODUuMCwgdGhpcyBtZXRob2QgZ3JhbnRlZCB0aGUgYHMzOlB1dE9iamVjdCpgIHBlcm1pc3Npb24gdGhhdCBpbmNsdWRlZCBgczM6UHV0T2JqZWN0QWNsYCxcbiAgICogd2hpY2ggY291bGQgYmUgdXNlZCB0byBncmFudCByZWFkL3dyaXRlIG9iamVjdCBhY2Nlc3MgdG8gSUFNIHByaW5jaXBhbHMgaW4gb3RoZXIgYWNjb3VudHMuXG4gICAqIElmIHlvdSB3YW50IHRvIGdldCByaWQgb2YgdGhhdCBiZWhhdmlvciwgdXBkYXRlIHlvdXIgQ0RLIHZlcnNpb24gdG8gMS44NS4wIG9yIGxhdGVyLFxuICAgKiBhbmQgbWFrZSBzdXJlIHRoZSBgQGF3cy1jZGsvYXdzLXMzOmdyYW50V3JpdGVXaXRob3V0QWNsYCBmZWF0dXJlIGZsYWcgaXMgc2V0IHRvIGB0cnVlYFxuICAgKiBpbiB0aGUgYGNvbnRleHRgIGtleSBvZiB5b3VyIGNkay5qc29uIGZpbGUuXG4gICAqIElmIHlvdSd2ZSBhbHJlYWR5IHVwZGF0ZWQsIGJ1dCBzdGlsbCBuZWVkIHRoZSBwcmluY2lwYWwgdG8gaGF2ZSBwZXJtaXNzaW9ucyB0byBtb2RpZnkgdGhlIEFDTHMsXG4gICAqIHVzZSB0aGUge0BsaW5rIGdyYW50UHV0QWNsfSBtZXRob2QuXG4gICAqXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgZ3JhbnRSZWFkV3JpdGUoaWRlbnRpdHk6IGlhbS5JR3JhbnRhYmxlLCBvYmplY3RzS2V5UGF0dGVybj86IGFueSk6IGlhbS5HcmFudDtcblxuICAvKipcbiAgICogQWxsb3dzIHVucmVzdHJpY3RlZCBhY2Nlc3MgdG8gb2JqZWN0cyBmcm9tIHRoaXMgYnVja2V0LlxuICAgKlxuICAgKiBJTVBPUlRBTlQ6IFRoaXMgcGVybWlzc2lvbiBhbGxvd3MgYW55b25lIHRvIHBlcmZvcm0gYWN0aW9ucyBvbiBTMyBvYmplY3RzXG4gICAqIGluIHRoaXMgYnVja2V0LCB3aGljaCBpcyB1c2VmdWwgZm9yIHdoZW4geW91IGNvbmZpZ3VyZSB5b3VyIGJ1Y2tldCBhcyBhXG4gICAqIHdlYnNpdGUgYW5kIHdhbnQgZXZlcnlvbmUgdG8gYmUgYWJsZSB0byByZWFkIG9iamVjdHMgaW4gdGhlIGJ1Y2tldCB3aXRob3V0XG4gICAqIG5lZWRpbmcgdG8gYXV0aGVudGljYXRlLlxuICAgKlxuICAgKiBXaXRob3V0IGFyZ3VtZW50cywgdGhpcyBtZXRob2Qgd2lsbCBncmFudCByZWFkIChcInMzOkdldE9iamVjdFwiKSBhY2Nlc3MgdG9cbiAgICogYWxsIG9iamVjdHMgKFwiKlwiKSBpbiB0aGUgYnVja2V0LlxuICAgKlxuICAgKiBUaGUgbWV0aG9kIHJldHVybnMgdGhlIGBpYW0uR3JhbnRgIG9iamVjdCwgd2hpY2ggY2FuIHRoZW4gYmUgbW9kaWZpZWRcbiAgICogYXMgbmVlZGVkLiBGb3IgZXhhbXBsZSwgeW91IGNhbiBhZGQgYSBjb25kaXRpb24gdGhhdCB3aWxsIHJlc3RyaWN0IGFjY2VzcyBvbmx5XG4gICAqIHRvIGFuIElQdjQgcmFuZ2UgbGlrZSB0aGlzOlxuICAgKlxuICAgKiAgICAgY29uc3QgZ3JhbnQgPSBidWNrZXQuZ3JhbnRQdWJsaWNBY2Nlc3MoKTtcbiAgICogICAgIGdyYW50LnJlc291cmNlU3RhdGVtZW50IS5hZGRDb25kaXRpb24o4oCYSXBBZGRyZXNz4oCZLCB7IOKAnGF3czpTb3VyY2VJcOKAnTog4oCcNTQuMjQwLjE0My4wLzI04oCdIH0pO1xuICAgKlxuICAgKlxuICAgKiBAcGFyYW0ga2V5UHJlZml4IHRoZSBwcmVmaXggb2YgUzMgb2JqZWN0IGtleXMgKGUuZy4gYGhvbWUvKmApLiBEZWZhdWx0IGlzIFwiKlwiLlxuICAgKiBAcGFyYW0gYWxsb3dlZEFjdGlvbnMgdGhlIHNldCBvZiBTMyBhY3Rpb25zIHRvIGFsbG93LiBEZWZhdWx0IGlzIFwiczM6R2V0T2JqZWN0XCIuXG4gICAqIEByZXR1cm5zIFRoZSBgaWFtLlBvbGljeVN0YXRlbWVudGAgb2JqZWN0LCB3aGljaCBjYW4gYmUgdXNlZCB0byBhcHBseSBlLmcuIGNvbmRpdGlvbnMuXG4gICAqL1xuICBncmFudFB1YmxpY0FjY2VzcyhrZXlQcmVmaXg/OiBzdHJpbmcsIC4uLmFsbG93ZWRBY3Rpb25zOiBzdHJpbmdbXSk6IGlhbS5HcmFudDtcblxuICAvKipcbiAgICogRGVmaW5lcyBhIENsb3VkV2F0Y2ggZXZlbnQgdGhhdCB0cmlnZ2VycyB3aGVuIHNvbWV0aGluZyBoYXBwZW5zIHRvIHRoaXMgYnVja2V0XG4gICAqXG4gICAqIFJlcXVpcmVzIHRoYXQgdGhlcmUgZXhpc3RzIGF0IGxlYXN0IG9uZSBDbG91ZFRyYWlsIFRyYWlsIGluIHlvdXIgYWNjb3VudFxuICAgKiB0aGF0IGNhcHR1cmVzIHRoZSBldmVudC4gVGhpcyBtZXRob2Qgd2lsbCBub3QgY3JlYXRlIHRoZSBUcmFpbC5cbiAgICpcbiAgICogQHBhcmFtIGlkIFRoZSBpZCBvZiB0aGUgcnVsZVxuICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25zIGZvciBhZGRpbmcgdGhlIHJ1bGVcbiAgICovXG4gIG9uQ2xvdWRUcmFpbEV2ZW50KGlkOiBzdHJpbmcsIG9wdGlvbnM/OiBPbkNsb3VkVHJhaWxCdWNrZXRFdmVudE9wdGlvbnMpOiBldmVudHMuUnVsZTtcblxuICAvKipcbiAgICogRGVmaW5lcyBhbiBBV1MgQ2xvdWRXYXRjaCBldmVudCB0aGF0IHRyaWdnZXJzIHdoZW4gYW4gb2JqZWN0IGlzIHVwbG9hZGVkXG4gICAqIHRvIHRoZSBzcGVjaWZpZWQgcGF0aHMgKGtleXMpIGluIHRoaXMgYnVja2V0IHVzaW5nIHRoZSBQdXRPYmplY3QgQVBJIGNhbGwuXG4gICAqXG4gICAqIE5vdGUgdGhhdCBzb21lIHRvb2xzIGxpa2UgYGF3cyBzMyBjcGAgd2lsbCBhdXRvbWF0aWNhbGx5IHVzZSBlaXRoZXJcbiAgICogUHV0T2JqZWN0IG9yIHRoZSBtdWx0aXBhcnQgdXBsb2FkIEFQSSBkZXBlbmRpbmcgb24gdGhlIGZpbGUgc2l6ZSxcbiAgICogc28gdXNpbmcgYG9uQ2xvdWRUcmFpbFdyaXRlT2JqZWN0YCBtYXkgYmUgcHJlZmVyYWJsZS5cbiAgICpcbiAgICogUmVxdWlyZXMgdGhhdCB0aGVyZSBleGlzdHMgYXQgbGVhc3Qgb25lIENsb3VkVHJhaWwgVHJhaWwgaW4geW91ciBhY2NvdW50XG4gICAqIHRoYXQgY2FwdHVyZXMgdGhlIGV2ZW50LiBUaGlzIG1ldGhvZCB3aWxsIG5vdCBjcmVhdGUgdGhlIFRyYWlsLlxuICAgKlxuICAgKiBAcGFyYW0gaWQgVGhlIGlkIG9mIHRoZSBydWxlXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbnMgZm9yIGFkZGluZyB0aGUgcnVsZVxuICAgKi9cbiAgb25DbG91ZFRyYWlsUHV0T2JqZWN0KGlkOiBzdHJpbmcsIG9wdGlvbnM/OiBPbkNsb3VkVHJhaWxCdWNrZXRFdmVudE9wdGlvbnMpOiBldmVudHMuUnVsZTtcblxuICAvKipcbiAgICogRGVmaW5lcyBhbiBBV1MgQ2xvdWRXYXRjaCBldmVudCB0aGF0IHRyaWdnZXJzIHdoZW4gYW4gb2JqZWN0IGF0IHRoZVxuICAgKiBzcGVjaWZpZWQgcGF0aHMgKGtleXMpIGluIHRoaXMgYnVja2V0IGFyZSB3cml0dGVuIHRvLiAgVGhpcyBpbmNsdWRlc1xuICAgKiB0aGUgZXZlbnRzIFB1dE9iamVjdCwgQ29weU9iamVjdCwgYW5kIENvbXBsZXRlTXVsdGlwYXJ0VXBsb2FkLlxuICAgKlxuICAgKiBOb3RlIHRoYXQgc29tZSB0b29scyBsaWtlIGBhd3MgczMgY3BgIHdpbGwgYXV0b21hdGljYWxseSB1c2UgZWl0aGVyXG4gICAqIFB1dE9iamVjdCBvciB0aGUgbXVsdGlwYXJ0IHVwbG9hZCBBUEkgZGVwZW5kaW5nIG9uIHRoZSBmaWxlIHNpemUsXG4gICAqIHNvIHVzaW5nIHRoaXMgbWV0aG9kIG1heSBiZSBwcmVmZXJhYmxlIHRvIGBvbkNsb3VkVHJhaWxQdXRPYmplY3RgLlxuICAgKlxuICAgKiBSZXF1aXJlcyB0aGF0IHRoZXJlIGV4aXN0cyBhdCBsZWFzdCBvbmUgQ2xvdWRUcmFpbCBUcmFpbCBpbiB5b3VyIGFjY291bnRcbiAgICogdGhhdCBjYXB0dXJlcyB0aGUgZXZlbnQuIFRoaXMgbWV0aG9kIHdpbGwgbm90IGNyZWF0ZSB0aGUgVHJhaWwuXG4gICAqXG4gICAqIEBwYXJhbSBpZCBUaGUgaWQgb2YgdGhlIHJ1bGVcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9ucyBmb3IgYWRkaW5nIHRoZSBydWxlXG4gICAqL1xuICBvbkNsb3VkVHJhaWxXcml0ZU9iamVjdChpZDogc3RyaW5nLCBvcHRpb25zPzogT25DbG91ZFRyYWlsQnVja2V0RXZlbnRPcHRpb25zKTogZXZlbnRzLlJ1bGU7XG5cbiAgLyoqXG4gICAqIEFkZHMgYSBidWNrZXQgbm90aWZpY2F0aW9uIGV2ZW50IGRlc3RpbmF0aW9uLlxuICAgKiBAcGFyYW0gZXZlbnQgVGhlIGV2ZW50IHRvIHRyaWdnZXIgdGhlIG5vdGlmaWNhdGlvblxuICAgKiBAcGFyYW0gZGVzdCBUaGUgbm90aWZpY2F0aW9uIGRlc3RpbmF0aW9uIChMYW1iZGEsIFNOUyBUb3BpYyBvciBTUVMgUXVldWUpXG4gICAqXG4gICAqIEBwYXJhbSBmaWx0ZXJzIFMzIG9iamVjdCBrZXkgZmlsdGVyIHJ1bGVzIHRvIGRldGVybWluZSB3aGljaCBvYmplY3RzXG4gICAqIHRyaWdnZXIgdGhpcyBldmVudC4gRWFjaCBmaWx0ZXIgbXVzdCBpbmNsdWRlIGEgYHByZWZpeGAgYW5kL29yIGBzdWZmaXhgXG4gICAqIHRoYXQgd2lsbCBiZSBtYXRjaGVkIGFnYWluc3QgdGhlIHMzIG9iamVjdCBrZXkuIFJlZmVyIHRvIHRoZSBTMyBEZXZlbG9wZXIgR3VpZGVcbiAgICogZm9yIGRldGFpbHMgYWJvdXQgYWxsb3dlZCBmaWx0ZXIgcnVsZXMuXG4gICAqXG4gICAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvTm90aWZpY2F0aW9uSG93VG8uaHRtbCNub3RpZmljYXRpb24taG93LXRvLWZpbHRlcmluZ1xuICAgKlxuICAgKiBAZXhhbXBsZVxuICAgKlxuICAgKiAgICBkZWNsYXJlIGNvbnN0IG15TGFtYmRhOiBsYW1iZGEuRnVuY3Rpb247XG4gICAqICAgIGNvbnN0IGJ1Y2tldCA9IG5ldyBzMy5CdWNrZXQodGhpcywgJ015QnVja2V0Jyk7XG4gICAqICAgIGJ1Y2tldC5hZGRFdmVudE5vdGlmaWNhdGlvbihzMy5FdmVudFR5cGUuT0JKRUNUX0NSRUFURUQsIG5ldyBzM24uTGFtYmRhRGVzdGluYXRpb24obXlMYW1iZGEpLCB7cHJlZml4OiAnaG9tZS9teXVzZXJuYW1lLyonfSlcbiAgICpcbiAgICogQHNlZVxuICAgKiBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9Ob3RpZmljYXRpb25Ib3dUby5odG1sXG4gICAqL1xuICBhZGRFdmVudE5vdGlmaWNhdGlvbihldmVudDogRXZlbnRUeXBlLCBkZXN0OiBJQnVja2V0Tm90aWZpY2F0aW9uRGVzdGluYXRpb24sIC4uLmZpbHRlcnM6IE5vdGlmaWNhdGlvbktleUZpbHRlcltdKTogdm9pZDtcblxuICAvKipcbiAgICogU3Vic2NyaWJlcyBhIGRlc3RpbmF0aW9uIHRvIHJlY2VpdmUgbm90aWZpY2F0aW9ucyB3aGVuIGFuIG9iamVjdCBpc1xuICAgKiBjcmVhdGVkIGluIHRoZSBidWNrZXQuIFRoaXMgaXMgaWRlbnRpY2FsIHRvIGNhbGxpbmdcbiAgICogYG9uRXZlbnQoczMuRXZlbnRUeXBlLk9CSkVDVF9DUkVBVEVEKWAuXG4gICAqXG4gICAqIEBwYXJhbSBkZXN0IFRoZSBub3RpZmljYXRpb24gZGVzdGluYXRpb24gKHNlZSBvbkV2ZW50KVxuICAgKiBAcGFyYW0gZmlsdGVycyBGaWx0ZXJzIChzZWUgb25FdmVudClcbiAgICovXG4gIGFkZE9iamVjdENyZWF0ZWROb3RpZmljYXRpb24oZGVzdDogSUJ1Y2tldE5vdGlmaWNhdGlvbkRlc3RpbmF0aW9uLCAuLi5maWx0ZXJzOiBOb3RpZmljYXRpb25LZXlGaWx0ZXJbXSk6IHZvaWRcblxuICAvKipcbiAgICogU3Vic2NyaWJlcyBhIGRlc3RpbmF0aW9uIHRvIHJlY2VpdmUgbm90aWZpY2F0aW9ucyB3aGVuIGFuIG9iamVjdCBpc1xuICAgKiByZW1vdmVkIGZyb20gdGhlIGJ1Y2tldC4gVGhpcyBpcyBpZGVudGljYWwgdG8gY2FsbGluZ1xuICAgKiBgb25FdmVudChFdmVudFR5cGUuT0JKRUNUX1JFTU9WRUQpYC5cbiAgICpcbiAgICogQHBhcmFtIGRlc3QgVGhlIG5vdGlmaWNhdGlvbiBkZXN0aW5hdGlvbiAoc2VlIG9uRXZlbnQpXG4gICAqIEBwYXJhbSBmaWx0ZXJzIEZpbHRlcnMgKHNlZSBvbkV2ZW50KVxuICAgKi9cbiAgYWRkT2JqZWN0UmVtb3ZlZE5vdGlmaWNhdGlvbihkZXN0OiBJQnVja2V0Tm90aWZpY2F0aW9uRGVzdGluYXRpb24sIC4uLmZpbHRlcnM6IE5vdGlmaWNhdGlvbktleUZpbHRlcltdKTogdm9pZDtcblxuXG4gIC8qKlxuICAgKiBFbmFibGVzIGV2ZW50IGJyaWRnZSBub3RpZmljYXRpb24sIGNhdXNpbmcgYWxsIGV2ZW50cyBiZWxvdyB0byBiZSBzZW50IHRvIEV2ZW50QnJpZGdlOlxuICAgKlxuICAgKiAtIE9iamVjdCBEZWxldGVkIChEZWxldGVPYmplY3QpXG4gICAqIC0gT2JqZWN0IERlbGV0ZWQgKExpZmVjeWNsZSBleHBpcmF0aW9uKVxuICAgKiAtIE9iamVjdCBSZXN0b3JlIEluaXRpYXRlZFxuICAgKiAtIE9iamVjdCBSZXN0b3JlIENvbXBsZXRlZFxuICAgKiAtIE9iamVjdCBSZXN0b3JlIEV4cGlyZWRcbiAgICogLSBPYmplY3QgU3RvcmFnZSBDbGFzcyBDaGFuZ2VkXG4gICAqIC0gT2JqZWN0IEFjY2VzcyBUaWVyIENoYW5nZWRcbiAgICogLSBPYmplY3QgQUNMIFVwZGF0ZWRcbiAgICogLSBPYmplY3QgVGFncyBBZGRlZFxuICAgKiAtIE9iamVjdCBUYWdzIERlbGV0ZWRcbiAgICovXG4gIGVuYWJsZUV2ZW50QnJpZGdlTm90aWZpY2F0aW9uKCk6IHZvaWQ7XG59XG5cbi8qKlxuICogQSByZWZlcmVuY2UgdG8gYSBidWNrZXQgb3V0c2lkZSB0aGlzIHN0YWNrXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgQnVja2V0QXR0cmlidXRlcyB7XG4gIC8qKlxuICAgKiBUaGUgQVJOIG9mIHRoZSBidWNrZXQuIEF0IGxlYXN0IG9uZSBvZiBidWNrZXRBcm4gb3IgYnVja2V0TmFtZSBtdXN0IGJlXG4gICAqIGRlZmluZWQgaW4gb3JkZXIgdG8gaW5pdGlhbGl6ZSBhIGJ1Y2tldCByZWYuXG4gICAqL1xuICByZWFkb25seSBidWNrZXRBcm4/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBuYW1lIG9mIHRoZSBidWNrZXQuIElmIHRoZSB1bmRlcmx5aW5nIHZhbHVlIG9mIEFSTiBpcyBhIHN0cmluZywgdGhlXG4gICAqIG5hbWUgd2lsbCBiZSBwYXJzZWQgZnJvbSB0aGUgQVJOLiBPdGhlcndpc2UsIHRoZSBuYW1lIGlzIG9wdGlvbmFsLCBidXRcbiAgICogc29tZSBmZWF0dXJlcyB0aGF0IHJlcXVpcmUgdGhlIGJ1Y2tldCBuYW1lIHN1Y2ggYXMgYXV0by1jcmVhdGluZyBhIGJ1Y2tldFxuICAgKiBwb2xpY3ksIHdvbid0IHdvcmsuXG4gICAqL1xuICByZWFkb25seSBidWNrZXROYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgZG9tYWluIG5hbWUgb2YgdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogQGRlZmF1bHQgSW5mZXJyZWQgZnJvbSBidWNrZXQgbmFtZVxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0RG9tYWluTmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHdlYnNpdGUgVVJMIG9mIHRoZSBidWNrZXQgKGlmIHN0YXRpYyB3ZWIgaG9zdGluZyBpcyBlbmFibGVkKS5cbiAgICpcbiAgICogQGRlZmF1bHQgSW5mZXJyZWQgZnJvbSBidWNrZXQgbmFtZVxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0V2Vic2l0ZVVybD86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHJlZ2lvbmFsIGRvbWFpbiBuYW1lIG9mIHRoZSBzcGVjaWZpZWQgYnVja2V0LlxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0UmVnaW9uYWxEb21haW5OYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgSVB2NiBETlMgbmFtZSBvZiB0aGUgc3BlY2lmaWVkIGJ1Y2tldC5cbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldER1YWxTdGFja0RvbWFpbk5hbWU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBmb3JtYXQgb2YgdGhlIHdlYnNpdGUgVVJMIG9mIHRoZSBidWNrZXQuIFRoaXMgc2hvdWxkIGJlIHRydWUgZm9yXG4gICAqIHJlZ2lvbnMgbGF1bmNoZWQgc2luY2UgMjAxNC5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldFdlYnNpdGVOZXdVcmxGb3JtYXQ/OiBib29sZWFuO1xuXG4gIHJlYWRvbmx5IGVuY3J5cHRpb25LZXk/OiBrbXMuSUtleTtcblxuICAvKipcbiAgICogSWYgdGhpcyBidWNrZXQgaGFzIGJlZW4gY29uZmlndXJlZCBmb3Igc3RhdGljIHdlYnNpdGUgaG9zdGluZy5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGlzV2Vic2l0ZT86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBhY2NvdW50IHRoaXMgZXhpc3RpbmcgYnVja2V0IGJlbG9uZ3MgdG8uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gaXQncyBhc3N1bWVkIHRoZSBidWNrZXQgYmVsb25ncyB0byB0aGUgc2FtZSBhY2NvdW50IGFzIHRoZSBzY29wZSBpdCdzIGJlaW5nIGltcG9ydGVkIGludG9cbiAgICovXG4gIHJlYWRvbmx5IGFjY291bnQ/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSByZWdpb24gdGhpcyBleGlzdGluZyBidWNrZXQgaXMgaW4uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gaXQncyBhc3N1bWVkIHRoZSBidWNrZXQgaXMgaW4gdGhlIHNhbWUgcmVnaW9uIGFzIHRoZSBzY29wZSBpdCdzIGJlaW5nIGltcG9ydGVkIGludG9cbiAgICovXG4gIHJlYWRvbmx5IHJlZ2lvbj86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHJvbGUgdG8gYmUgdXNlZCBieSB0aGUgbm90aWZpY2F0aW9ucyBoYW5kbGVyXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gYSBuZXcgcm9sZSB3aWxsIGJlIGNyZWF0ZWQuXG4gICAqL1xuICByZWFkb25seSBub3RpZmljYXRpb25zSGFuZGxlclJvbGU/OiBpYW0uSVJvbGU7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhbiBTMyBCdWNrZXQuXG4gKlxuICogQnVja2V0cyBjYW4gYmUgZWl0aGVyIGRlZmluZWQgd2l0aGluIHRoaXMgc3RhY2s6XG4gKlxuICogICBuZXcgQnVja2V0KHRoaXMsICdNeUJ1Y2tldCcsIHsgcHJvcHMgfSk7XG4gKlxuICogT3IgaW1wb3J0ZWQgZnJvbSBhbiBleGlzdGluZyBidWNrZXQ6XG4gKlxuICogICBCdWNrZXQuaW1wb3J0KHRoaXMsICdNeUltcG9ydGVkQnVja2V0JywgeyBidWNrZXRBcm46IC4uLiB9KTtcbiAqXG4gKiBZb3UgY2FuIGFsc28gZXhwb3J0IGEgYnVja2V0IGFuZCBpbXBvcnQgaXQgaW50byBhbm90aGVyIHN0YWNrOlxuICpcbiAqICAgY29uc3QgcmVmID0gbXlCdWNrZXQuZXhwb3J0KCk7XG4gKiAgIEJ1Y2tldC5pbXBvcnQodGhpcywgJ015SW1wb3J0ZWRCdWNrZXQnLCByZWYpO1xuICpcbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEJ1Y2tldEJhc2UgZXh0ZW5kcyBSZXNvdXJjZSBpbXBsZW1lbnRzIElCdWNrZXQge1xuICBwdWJsaWMgYWJzdHJhY3QgcmVhZG9ubHkgYnVja2V0QXJuOiBzdHJpbmc7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBidWNrZXROYW1lOiBzdHJpbmc7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBidWNrZXREb21haW5OYW1lOiBzdHJpbmc7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBidWNrZXRXZWJzaXRlVXJsOiBzdHJpbmc7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBidWNrZXRXZWJzaXRlRG9tYWluTmFtZTogc3RyaW5nO1xuICBwdWJsaWMgYWJzdHJhY3QgcmVhZG9ubHkgYnVja2V0UmVnaW9uYWxEb21haW5OYW1lOiBzdHJpbmc7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBidWNrZXREdWFsU3RhY2tEb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIE9wdGlvbmFsIEtNUyBlbmNyeXB0aW9uIGtleSBhc3NvY2lhdGVkIHdpdGggdGhpcyBidWNrZXQuXG4gICAqL1xuICBwdWJsaWMgYWJzdHJhY3QgcmVhZG9ubHkgZW5jcnlwdGlvbktleT86IGttcy5JS2V5O1xuXG4gIC8qKlxuICAgKiBJZiB0aGlzIGJ1Y2tldCBoYXMgYmVlbiBjb25maWd1cmVkIGZvciBzdGF0aWMgd2Vic2l0ZSBob3N0aW5nLlxuICAgKi9cbiAgcHVibGljIGFic3RyYWN0IHJlYWRvbmx5IGlzV2Vic2l0ZT86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSByZXNvdXJjZSBwb2xpY3kgYXNzb2NpYXRlZCB3aXRoIHRoaXMgYnVja2V0LlxuICAgKlxuICAgKiBJZiBgYXV0b0NyZWF0ZVBvbGljeWAgaXMgdHJ1ZSwgYSBgQnVja2V0UG9saWN5YCB3aWxsIGJlIGNyZWF0ZWQgdXBvbiB0aGVcbiAgICogZmlyc3QgY2FsbCB0byBhZGRUb1Jlc291cmNlUG9saWN5KHMpLlxuICAgKi9cbiAgcHVibGljIGFic3RyYWN0IHBvbGljeT86IEJ1Y2tldFBvbGljeTtcblxuICAvKipcbiAgICogSW5kaWNhdGVzIGlmIGEgYnVja2V0IHJlc291cmNlIHBvbGljeSBzaG91bGQgYXV0b21hdGljYWxseSBjcmVhdGVkIHVwb25cbiAgICogdGhlIGZpcnN0IGNhbGwgdG8gYGFkZFRvUmVzb3VyY2VQb2xpY3lgLlxuICAgKi9cbiAgcHJvdGVjdGVkIGFic3RyYWN0IGF1dG9DcmVhdGVQb2xpY3k6IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gZGlzYWxsb3cgcHVibGljIGFjY2Vzc1xuICAgKi9cbiAgcHJvdGVjdGVkIGFic3RyYWN0IGRpc2FsbG93UHVibGljQWNjZXNzPzogYm9vbGVhbjtcblxuICBwcml2YXRlIG5vdGlmaWNhdGlvbnM/OiBCdWNrZXROb3RpZmljYXRpb25zO1xuXG4gIHByb3RlY3RlZCBub3RpZmljYXRpb25zSGFuZGxlclJvbGU/OiBpYW0uSVJvbGU7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IFJlc291cmNlUHJvcHMgPSB7fSkge1xuICAgIHN1cGVyKHNjb3BlLCBpZCwgcHJvcHMpO1xuXG4gICAgdGhpcy5ub2RlLmFkZFZhbGlkYXRpb24oeyB2YWxpZGF0ZTogKCkgPT4gdGhpcy5wb2xpY3k/LmRvY3VtZW50LnZhbGlkYXRlRm9yUmVzb3VyY2VQb2xpY3koKSA/PyBbXSB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBEZWZpbmUgYSBDbG91ZFdhdGNoIGV2ZW50IHRoYXQgdHJpZ2dlcnMgd2hlbiBzb21ldGhpbmcgaGFwcGVucyB0byB0aGlzIHJlcG9zaXRvcnlcbiAgICpcbiAgICogUmVxdWlyZXMgdGhhdCB0aGVyZSBleGlzdHMgYXQgbGVhc3Qgb25lIENsb3VkVHJhaWwgVHJhaWwgaW4geW91ciBhY2NvdW50XG4gICAqIHRoYXQgY2FwdHVyZXMgdGhlIGV2ZW50LiBUaGlzIG1ldGhvZCB3aWxsIG5vdCBjcmVhdGUgdGhlIFRyYWlsLlxuICAgKlxuICAgKiBAcGFyYW0gaWQgVGhlIGlkIG9mIHRoZSBydWxlXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbnMgZm9yIGFkZGluZyB0aGUgcnVsZVxuICAgKi9cbiAgcHVibGljIG9uQ2xvdWRUcmFpbEV2ZW50KGlkOiBzdHJpbmcsIG9wdGlvbnM6IE9uQ2xvdWRUcmFpbEJ1Y2tldEV2ZW50T3B0aW9ucyA9IHt9KTogZXZlbnRzLlJ1bGUge1xuICAgIGNvbnN0IHJ1bGUgPSBuZXcgZXZlbnRzLlJ1bGUodGhpcywgaWQsIG9wdGlvbnMpO1xuICAgIHJ1bGUuYWRkVGFyZ2V0KG9wdGlvbnMudGFyZ2V0KTtcbiAgICBydWxlLmFkZEV2ZW50UGF0dGVybih7XG4gICAgICBzb3VyY2U6IFsnYXdzLnMzJ10sXG4gICAgICBkZXRhaWxUeXBlOiBbJ0FXUyBBUEkgQ2FsbCB2aWEgQ2xvdWRUcmFpbCddLFxuICAgICAgZGV0YWlsOiB7XG4gICAgICAgIHJlc291cmNlczoge1xuICAgICAgICAgIEFSTjogb3B0aW9ucy5wYXRocz8ubWFwKHAgPT4gdGhpcy5hcm5Gb3JPYmplY3RzKHApKSA/PyBbdGhpcy5idWNrZXRBcm5dLFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9KTtcbiAgICByZXR1cm4gcnVsZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBEZWZpbmVzIGFuIEFXUyBDbG91ZFdhdGNoIGV2ZW50IHRoYXQgdHJpZ2dlcnMgd2hlbiBhbiBvYmplY3QgaXMgdXBsb2FkZWRcbiAgICogdG8gdGhlIHNwZWNpZmllZCBwYXRocyAoa2V5cykgaW4gdGhpcyBidWNrZXQgdXNpbmcgdGhlIFB1dE9iamVjdCBBUEkgY2FsbC5cbiAgICpcbiAgICogTm90ZSB0aGF0IHNvbWUgdG9vbHMgbGlrZSBgYXdzIHMzIGNwYCB3aWxsIGF1dG9tYXRpY2FsbHkgdXNlIGVpdGhlclxuICAgKiBQdXRPYmplY3Qgb3IgdGhlIG11bHRpcGFydCB1cGxvYWQgQVBJIGRlcGVuZGluZyBvbiB0aGUgZmlsZSBzaXplLFxuICAgKiBzbyB1c2luZyBgb25DbG91ZFRyYWlsV3JpdGVPYmplY3RgIG1heSBiZSBwcmVmZXJhYmxlLlxuICAgKlxuICAgKiBSZXF1aXJlcyB0aGF0IHRoZXJlIGV4aXN0cyBhdCBsZWFzdCBvbmUgQ2xvdWRUcmFpbCBUcmFpbCBpbiB5b3VyIGFjY291bnRcbiAgICogdGhhdCBjYXB0dXJlcyB0aGUgZXZlbnQuIFRoaXMgbWV0aG9kIHdpbGwgbm90IGNyZWF0ZSB0aGUgVHJhaWwuXG4gICAqXG4gICAqIEBwYXJhbSBpZCBUaGUgaWQgb2YgdGhlIHJ1bGVcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9ucyBmb3IgYWRkaW5nIHRoZSBydWxlXG4gICAqL1xuICBwdWJsaWMgb25DbG91ZFRyYWlsUHV0T2JqZWN0KGlkOiBzdHJpbmcsIG9wdGlvbnM6IE9uQ2xvdWRUcmFpbEJ1Y2tldEV2ZW50T3B0aW9ucyA9IHt9KTogZXZlbnRzLlJ1bGUge1xuICAgIGNvbnN0IHJ1bGUgPSB0aGlzLm9uQ2xvdWRUcmFpbEV2ZW50KGlkLCBvcHRpb25zKTtcbiAgICBydWxlLmFkZEV2ZW50UGF0dGVybih7XG4gICAgICBkZXRhaWw6IHtcbiAgICAgICAgZXZlbnROYW1lOiBbJ1B1dE9iamVjdCddLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICByZXR1cm4gcnVsZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBEZWZpbmVzIGFuIEFXUyBDbG91ZFdhdGNoIGV2ZW50IHRoYXQgdHJpZ2dlcnMgd2hlbiBhbiBvYmplY3QgYXQgdGhlXG4gICAqIHNwZWNpZmllZCBwYXRocyAoa2V5cykgaW4gdGhpcyBidWNrZXQgYXJlIHdyaXR0ZW4gdG8uICBUaGlzIGluY2x1ZGVzXG4gICAqIHRoZSBldmVudHMgUHV0T2JqZWN0LCBDb3B5T2JqZWN0LCBhbmQgQ29tcGxldGVNdWx0aXBhcnRVcGxvYWQuXG4gICAqXG4gICAqIE5vdGUgdGhhdCBzb21lIHRvb2xzIGxpa2UgYGF3cyBzMyBjcGAgd2lsbCBhdXRvbWF0aWNhbGx5IHVzZSBlaXRoZXJcbiAgICogUHV0T2JqZWN0IG9yIHRoZSBtdWx0aXBhcnQgdXBsb2FkIEFQSSBkZXBlbmRpbmcgb24gdGhlIGZpbGUgc2l6ZSxcbiAgICogc28gdXNpbmcgdGhpcyBtZXRob2QgbWF5IGJlIHByZWZlcmFibGUgdG8gYG9uQ2xvdWRUcmFpbFB1dE9iamVjdGAuXG4gICAqXG4gICAqIFJlcXVpcmVzIHRoYXQgdGhlcmUgZXhpc3RzIGF0IGxlYXN0IG9uZSBDbG91ZFRyYWlsIFRyYWlsIGluIHlvdXIgYWNjb3VudFxuICAgKiB0aGF0IGNhcHR1cmVzIHRoZSBldmVudC4gVGhpcyBtZXRob2Qgd2lsbCBub3QgY3JlYXRlIHRoZSBUcmFpbC5cbiAgICpcbiAgICogQHBhcmFtIGlkIFRoZSBpZCBvZiB0aGUgcnVsZVxuICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25zIGZvciBhZGRpbmcgdGhlIHJ1bGVcbiAgICovXG4gIHB1YmxpYyBvbkNsb3VkVHJhaWxXcml0ZU9iamVjdChpZDogc3RyaW5nLCBvcHRpb25zOiBPbkNsb3VkVHJhaWxCdWNrZXRFdmVudE9wdGlvbnMgPSB7fSk6IGV2ZW50cy5SdWxlIHtcbiAgICBjb25zdCBydWxlID0gdGhpcy5vbkNsb3VkVHJhaWxFdmVudChpZCwgb3B0aW9ucyk7XG4gICAgcnVsZS5hZGRFdmVudFBhdHRlcm4oe1xuICAgICAgZGV0YWlsOiB7XG4gICAgICAgIGV2ZW50TmFtZTogW1xuICAgICAgICAgICdDb21wbGV0ZU11bHRpcGFydFVwbG9hZCcsXG4gICAgICAgICAgJ0NvcHlPYmplY3QnLFxuICAgICAgICAgICdQdXRPYmplY3QnLFxuICAgICAgICBdLFxuICAgICAgICByZXF1ZXN0UGFyYW1ldGVyczoge1xuICAgICAgICAgIGJ1Y2tldE5hbWU6IFt0aGlzLmJ1Y2tldE5hbWVdLFxuICAgICAgICAgIGtleTogb3B0aW9ucy5wYXRocyxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gICAgcmV0dXJuIHJ1bGU7XG4gIH1cblxuICAvKipcbiAgICogQWRkcyBhIHN0YXRlbWVudCB0byB0aGUgcmVzb3VyY2UgcG9saWN5IGZvciBhIHByaW5jaXBhbCAoaS5lLlxuICAgKiBhY2NvdW50L3JvbGUvc2VydmljZSkgdG8gcGVyZm9ybSBhY3Rpb25zIG9uIHRoaXMgYnVja2V0IGFuZC9vciBpdHNcbiAgICogY29udGVudHMuIFVzZSBgYnVja2V0QXJuYCBhbmQgYGFybkZvck9iamVjdHMoa2V5cylgIHRvIG9idGFpbiBBUk5zIGZvclxuICAgKiB0aGlzIGJ1Y2tldCBvciBvYmplY3RzLlxuICAgKlxuICAgKiBOb3RlIHRoYXQgdGhlIHBvbGljeSBzdGF0ZW1lbnQgbWF5IG9yIG1heSBub3QgYmUgYWRkZWQgdG8gdGhlIHBvbGljeS5cbiAgICogRm9yIGV4YW1wbGUsIHdoZW4gYW4gYElCdWNrZXRgIGlzIGNyZWF0ZWQgZnJvbSBhbiBleGlzdGluZyBidWNrZXQsXG4gICAqIGl0J3Mgbm90IHBvc3NpYmxlIHRvIHRlbGwgd2hldGhlciB0aGUgYnVja2V0IGFscmVhZHkgaGFzIGEgcG9saWN5XG4gICAqIGF0dGFjaGVkLCBsZXQgYWxvbmUgdG8gcmUtdXNlIHRoYXQgcG9saWN5IHRvIGFkZCBtb3JlIHN0YXRlbWVudHMgdG8gaXQuXG4gICAqIFNvIGl0J3Mgc2FmZXN0IHRvIGRvIG5vdGhpbmcgaW4gdGhlc2UgY2FzZXMuXG4gICAqXG4gICAqIEBwYXJhbSBwZXJtaXNzaW9uIHRoZSBwb2xpY3kgc3RhdGVtZW50IHRvIGJlIGFkZGVkIHRvIHRoZSBidWNrZXQnc1xuICAgKiBwb2xpY3kuXG4gICAqIEByZXR1cm5zIG1ldGFkYXRhIGFib3V0IHRoZSBleGVjdXRpb24gb2YgdGhpcyBtZXRob2QuIElmIHRoZSBwb2xpY3lcbiAgICogd2FzIG5vdCBhZGRlZCwgdGhlIHZhbHVlIG9mIGBzdGF0ZW1lbnRBZGRlZGAgd2lsbCBiZSBgZmFsc2VgLiBZb3VcbiAgICogc2hvdWxkIGFsd2F5cyBjaGVjayB0aGlzIHZhbHVlIHRvIG1ha2Ugc3VyZSB0aGF0IHRoZSBvcGVyYXRpb24gd2FzXG4gICAqIGFjdHVhbGx5IGNhcnJpZWQgb3V0LiBPdGhlcndpc2UsIHN5bnRoZXNpcyBhbmQgZGVwbG95IHdpbGwgdGVybWluYXRlXG4gICAqIHNpbGVudGx5LCB3aGljaCBtYXkgYmUgY29uZnVzaW5nLlxuICAgKi9cbiAgcHVibGljIGFkZFRvUmVzb3VyY2VQb2xpY3kocGVybWlzc2lvbjogaWFtLlBvbGljeVN0YXRlbWVudCk6IGlhbS5BZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0IHtcbiAgICBpZiAoIXRoaXMucG9saWN5ICYmIHRoaXMuYXV0b0NyZWF0ZVBvbGljeSkge1xuICAgICAgdGhpcy5wb2xpY3kgPSBuZXcgQnVja2V0UG9saWN5KHRoaXMsICdQb2xpY3knLCB7IGJ1Y2tldDogdGhpcyB9KTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5wb2xpY3kpIHtcbiAgICAgIHRoaXMucG9saWN5LmRvY3VtZW50LmFkZFN0YXRlbWVudHMocGVybWlzc2lvbik7XG4gICAgICByZXR1cm4geyBzdGF0ZW1lbnRBZGRlZDogdHJ1ZSwgcG9saWN5RGVwZW5kYWJsZTogdGhpcy5wb2xpY3kgfTtcbiAgICB9XG5cbiAgICByZXR1cm4geyBzdGF0ZW1lbnRBZGRlZDogZmFsc2UgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGUgaHR0cHMgVVJMIG9mIGFuIFMzIG9iamVjdC4gU3BlY2lmeSBgcmVnaW9uYWw6IGZhbHNlYCBhdCB0aGUgb3B0aW9uc1xuICAgKiBmb3Igbm9uLXJlZ2lvbmFsIFVSTHMuIEZvciBleGFtcGxlOlxuICAgKlxuICAgKiAtIGBodHRwczovL3MzLnVzLXdlc3QtMS5hbWF6b25hd3MuY29tL29ubHlidWNrZXRgXG4gICAqIC0gYGh0dHBzOi8vczMudXMtd2VzdC0xLmFtYXpvbmF3cy5jb20vYnVja2V0L2tleWBcbiAgICogLSBgaHR0cHM6Ly9zMy5jbi1ub3J0aC0xLmFtYXpvbmF3cy5jb20uY24vY2hpbmEtYnVja2V0L215a2V5YFxuICAgKlxuICAgKiBAcGFyYW0ga2V5IFRoZSBTMyBrZXkgb2YgdGhlIG9iamVjdC4gSWYgbm90IHNwZWNpZmllZCwgdGhlIFVSTCBvZiB0aGVcbiAgICogICAgICBidWNrZXQgaXMgcmV0dXJuZWQuXG4gICAqIEByZXR1cm5zIGFuIE9iamVjdFMzVXJsIHRva2VuXG4gICAqL1xuICBwdWJsaWMgdXJsRm9yT2JqZWN0KGtleT86IHN0cmluZyk6IHN0cmluZyB7XG4gICAgY29uc3Qgc3RhY2sgPSBTdGFjay5vZih0aGlzKTtcbiAgICBjb25zdCBwcmVmaXggPSBgaHR0cHM6Ly9zMy4ke3RoaXMuZW52LnJlZ2lvbn0uJHtzdGFjay51cmxTdWZmaXh9L2A7XG4gICAgaWYgKHR5cGVvZiBrZXkgIT09ICdzdHJpbmcnKSB7XG4gICAgICByZXR1cm4gdGhpcy51cmxKb2luKHByZWZpeCwgdGhpcy5idWNrZXROYW1lKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMudXJsSm9pbihwcmVmaXgsIHRoaXMuYnVja2V0TmFtZSwga2V5KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGUgaHR0cHMgVHJhbnNmZXIgQWNjZWxlcmF0aW9uIFVSTCBvZiBhbiBTMyBvYmplY3QuIFNwZWNpZnkgYGR1YWxTdGFjazogdHJ1ZWAgYXQgdGhlIG9wdGlvbnNcbiAgICogZm9yIGR1YWwtc3RhY2sgZW5kcG9pbnQgKGNvbm5lY3QgdG8gdGhlIGJ1Y2tldCBvdmVyIElQdjYpLiBGb3IgZXhhbXBsZTpcbiAgICpcbiAgICogLSBgaHR0cHM6Ly9idWNrZXQuczMtYWNjZWxlcmF0ZS5hbWF6b25hd3MuY29tYFxuICAgKiAtIGBodHRwczovL2J1Y2tldC5zMy1hY2NlbGVyYXRlLmFtYXpvbmF3cy5jb20va2V5YFxuICAgKlxuICAgKiBAcGFyYW0ga2V5IFRoZSBTMyBrZXkgb2YgdGhlIG9iamVjdC4gSWYgbm90IHNwZWNpZmllZCwgdGhlIFVSTCBvZiB0aGVcbiAgICogICAgICBidWNrZXQgaXMgcmV0dXJuZWQuXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbnMgZm9yIGdlbmVyYXRpbmcgVVJMLlxuICAgKiBAcmV0dXJucyBhbiBUcmFuc2ZlckFjY2VsZXJhdGlvblVybCB0b2tlblxuICAgKi9cbiAgcHVibGljIHRyYW5zZmVyQWNjZWxlcmF0aW9uVXJsRm9yT2JqZWN0KGtleT86IHN0cmluZywgb3B0aW9ucz86IFRyYW5zZmVyQWNjZWxlcmF0aW9uVXJsT3B0aW9ucyk6IHN0cmluZyB7XG4gICAgY29uc3QgZHVhbFN0YWNrID0gb3B0aW9ucz8uZHVhbFN0YWNrID8gJy5kdWFsc3RhY2snIDogJyc7XG4gICAgY29uc3QgcHJlZml4ID0gYGh0dHBzOi8vJHt0aGlzLmJ1Y2tldE5hbWV9LnMzLWFjY2VsZXJhdGUke2R1YWxTdGFja30uYW1hem9uYXdzLmNvbS9gO1xuICAgIGlmICh0eXBlb2Yga2V5ICE9PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIHRoaXMudXJsSm9pbihwcmVmaXgpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy51cmxKb2luKHByZWZpeCwga2V5KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGUgdmlydHVhbCBob3N0ZWQtc3R5bGUgVVJMIG9mIGFuIFMzIG9iamVjdC4gU3BlY2lmeSBgcmVnaW9uYWw6IGZhbHNlYCBhdFxuICAgKiB0aGUgb3B0aW9ucyBmb3Igbm9uLXJlZ2lvbmFsIFVSTC4gRm9yIGV4YW1wbGU6XG4gICAqXG4gICAqIC0gYGh0dHBzOi8vb25seS1idWNrZXQuczMudXMtd2VzdC0xLmFtYXpvbmF3cy5jb21gXG4gICAqIC0gYGh0dHBzOi8vYnVja2V0LnMzLnVzLXdlc3QtMS5hbWF6b25hd3MuY29tL2tleWBcbiAgICogLSBgaHR0cHM6Ly9idWNrZXQuczMuYW1hem9uYXdzLmNvbS9rZXlgXG4gICAqIC0gYGh0dHBzOi8vY2hpbmEtYnVja2V0LnMzLmNuLW5vcnRoLTEuYW1hem9uYXdzLmNvbS5jbi9teWtleWBcbiAgICpcbiAgICogQHBhcmFtIGtleSBUaGUgUzMga2V5IG9mIHRoZSBvYmplY3QuIElmIG5vdCBzcGVjaWZpZWQsIHRoZSBVUkwgb2YgdGhlXG4gICAqICAgICAgYnVja2V0IGlzIHJldHVybmVkLlxuICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25zIGZvciBnZW5lcmF0aW5nIFVSTC5cbiAgICogQHJldHVybnMgYW4gT2JqZWN0UzNVcmwgdG9rZW5cbiAgICovXG4gIHB1YmxpYyB2aXJ0dWFsSG9zdGVkVXJsRm9yT2JqZWN0KGtleT86IHN0cmluZywgb3B0aW9ucz86IFZpcnR1YWxIb3N0ZWRTdHlsZVVybE9wdGlvbnMpOiBzdHJpbmcge1xuICAgIGNvbnN0IGRvbWFpbk5hbWUgPSBvcHRpb25zPy5yZWdpb25hbCA/PyB0cnVlID8gdGhpcy5idWNrZXRSZWdpb25hbERvbWFpbk5hbWUgOiB0aGlzLmJ1Y2tldERvbWFpbk5hbWU7XG4gICAgY29uc3QgcHJlZml4ID0gYGh0dHBzOi8vJHtkb21haW5OYW1lfWA7XG4gICAgaWYgKHR5cGVvZiBrZXkgIT09ICdzdHJpbmcnKSB7XG4gICAgICByZXR1cm4gcHJlZml4O1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy51cmxKb2luKHByZWZpeCwga2V5KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGUgUzMgVVJMIG9mIGFuIFMzIG9iamVjdC4gRm9yIGV4YW1wbGU6XG4gICAqXG4gICAqIC0gYHMzOi8vb25seWJ1Y2tldGBcbiAgICogLSBgczM6Ly9idWNrZXQva2V5YFxuICAgKlxuICAgKiBAcGFyYW0ga2V5IFRoZSBTMyBrZXkgb2YgdGhlIG9iamVjdC4gSWYgbm90IHNwZWNpZmllZCwgdGhlIFMzIFVSTCBvZiB0aGVcbiAgICogICAgICBidWNrZXQgaXMgcmV0dXJuZWQuXG4gICAqIEByZXR1cm5zIGFuIE9iamVjdFMzVXJsIHRva2VuXG4gICAqL1xuICBwdWJsaWMgczNVcmxGb3JPYmplY3Qoa2V5Pzogc3RyaW5nKTogc3RyaW5nIHtcbiAgICBjb25zdCBwcmVmaXggPSAnczM6Ly8nO1xuICAgIGlmICh0eXBlb2Yga2V5ICE9PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIHRoaXMudXJsSm9pbihwcmVmaXgsIHRoaXMuYnVja2V0TmFtZSk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLnVybEpvaW4ocHJlZml4LCB0aGlzLmJ1Y2tldE5hbWUsIGtleSk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyBhbiBBUk4gdGhhdCByZXByZXNlbnRzIGFsbCBvYmplY3RzIHdpdGhpbiB0aGUgYnVja2V0IHRoYXQgbWF0Y2hcbiAgICogdGhlIGtleSBwYXR0ZXJuIHNwZWNpZmllZC4gVG8gcmVwcmVzZW50IGFsbCBrZXlzLCBzcGVjaWZ5IGBgXCIqXCJgYC5cbiAgICpcbiAgICogSWYgeW91IG5lZWQgdG8gc3BlY2lmeSBhIGtleVBhdHRlcm4gd2l0aCBtdWx0aXBsZSBjb21wb25lbnRzLCBjb25jYXRlbmF0ZSB0aGVtIGludG8gYSBzaW5nbGUgc3RyaW5nLCBlLmcuOlxuICAgKlxuICAgKiAgIGFybkZvck9iamVjdHMoYGhvbWUvJHt0ZWFtfS8ke3VzZXJ9LypgKVxuICAgKlxuICAgKi9cbiAgcHVibGljIGFybkZvck9iamVjdHMoa2V5UGF0dGVybjogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5idWNrZXRBcm59LyR7a2V5UGF0dGVybn1gO1xuICB9XG5cbiAgLyoqXG4gICAqIEdyYW50IHJlYWQgcGVybWlzc2lvbnMgZm9yIHRoaXMgYnVja2V0IGFuZCBpdCdzIGNvbnRlbnRzIHRvIGFuIElBTVxuICAgKiBwcmluY2lwYWwgKFJvbGUvR3JvdXAvVXNlcikuXG4gICAqXG4gICAqIElmIGVuY3J5cHRpb24gaXMgdXNlZCwgcGVybWlzc2lvbiB0byB1c2UgdGhlIGtleSB0byBkZWNyeXB0IHRoZSBjb250ZW50c1xuICAgKiBvZiB0aGUgYnVja2V0IHdpbGwgYWxzbyBiZSBncmFudGVkIHRvIHRoZSBzYW1lIHByaW5jaXBhbC5cbiAgICpcbiAgICogQHBhcmFtIGlkZW50aXR5IFRoZSBwcmluY2lwYWxcbiAgICogQHBhcmFtIG9iamVjdHNLZXlQYXR0ZXJuIFJlc3RyaWN0IHRoZSBwZXJtaXNzaW9uIHRvIGEgY2VydGFpbiBrZXkgcGF0dGVybiAoZGVmYXVsdCAnKicpXG4gICAqL1xuICBwdWJsaWMgZ3JhbnRSZWFkKGlkZW50aXR5OiBpYW0uSUdyYW50YWJsZSwgb2JqZWN0c0tleVBhdHRlcm46IGFueSA9ICcqJykge1xuICAgIHJldHVybiB0aGlzLmdyYW50KGlkZW50aXR5LCBwZXJtcy5CVUNLRVRfUkVBRF9BQ1RJT05TLCBwZXJtcy5LRVlfUkVBRF9BQ1RJT05TLFxuICAgICAgdGhpcy5idWNrZXRBcm4sXG4gICAgICB0aGlzLmFybkZvck9iamVjdHMob2JqZWN0c0tleVBhdHRlcm4pKTtcbiAgfVxuXG4gIHB1YmxpYyBncmFudFdyaXRlKGlkZW50aXR5OiBpYW0uSUdyYW50YWJsZSwgb2JqZWN0c0tleVBhdHRlcm46IGFueSA9ICcqJykge1xuICAgIHJldHVybiB0aGlzLmdyYW50KGlkZW50aXR5LCB0aGlzLndyaXRlQWN0aW9ucywgcGVybXMuS0VZX1dSSVRFX0FDVElPTlMsXG4gICAgICB0aGlzLmJ1Y2tldEFybixcbiAgICAgIHRoaXMuYXJuRm9yT2JqZWN0cyhvYmplY3RzS2V5UGF0dGVybikpO1xuICB9XG5cbiAgLyoqXG4gICAqIEdyYW50cyBzMzpQdXRPYmplY3QqIGFuZCBzMzpBYm9ydCogcGVybWlzc2lvbnMgZm9yIHRoaXMgYnVja2V0IHRvIGFuIElBTSBwcmluY2lwYWwuXG4gICAqXG4gICAqIElmIGVuY3J5cHRpb24gaXMgdXNlZCwgcGVybWlzc2lvbiB0byB1c2UgdGhlIGtleSB0byBlbmNyeXB0IHRoZSBjb250ZW50c1xuICAgKiBvZiB3cml0dGVuIGZpbGVzIHdpbGwgYWxzbyBiZSBncmFudGVkIHRvIHRoZSBzYW1lIHByaW5jaXBhbC5cbiAgICogQHBhcmFtIGlkZW50aXR5IFRoZSBwcmluY2lwYWxcbiAgICogQHBhcmFtIG9iamVjdHNLZXlQYXR0ZXJuIFJlc3RyaWN0IHRoZSBwZXJtaXNzaW9uIHRvIGEgY2VydGFpbiBrZXkgcGF0dGVybiAoZGVmYXVsdCAnKicpXG4gICAqL1xuICBwdWJsaWMgZ3JhbnRQdXQoaWRlbnRpdHk6IGlhbS5JR3JhbnRhYmxlLCBvYmplY3RzS2V5UGF0dGVybjogYW55ID0gJyonKSB7XG4gICAgcmV0dXJuIHRoaXMuZ3JhbnQoaWRlbnRpdHksIHRoaXMucHV0QWN0aW9ucywgcGVybXMuS0VZX1dSSVRFX0FDVElPTlMsXG4gICAgICB0aGlzLmFybkZvck9iamVjdHMob2JqZWN0c0tleVBhdHRlcm4pKTtcbiAgfVxuXG4gIHB1YmxpYyBncmFudFB1dEFjbChpZGVudGl0eTogaWFtLklHcmFudGFibGUsIG9iamVjdHNLZXlQYXR0ZXJuOiBzdHJpbmcgPSAnKicpIHtcbiAgICByZXR1cm4gdGhpcy5ncmFudChpZGVudGl0eSwgcGVybXMuQlVDS0VUX1BVVF9BQ0xfQUNUSU9OUywgW10sXG4gICAgICB0aGlzLmFybkZvck9iamVjdHMob2JqZWN0c0tleVBhdHRlcm4pKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHcmFudHMgczM6RGVsZXRlT2JqZWN0KiBwZXJtaXNzaW9uIHRvIGFuIElBTSBwcmluY2lwYWwgZm9yIG9iamVjdHNcbiAgICogaW4gdGhpcyBidWNrZXQuXG4gICAqXG4gICAqIEBwYXJhbSBpZGVudGl0eSBUaGUgcHJpbmNpcGFsXG4gICAqIEBwYXJhbSBvYmplY3RzS2V5UGF0dGVybiBSZXN0cmljdCB0aGUgcGVybWlzc2lvbiB0byBhIGNlcnRhaW4ga2V5IHBhdHRlcm4gKGRlZmF1bHQgJyonKVxuICAgKi9cbiAgcHVibGljIGdyYW50RGVsZXRlKGlkZW50aXR5OiBpYW0uSUdyYW50YWJsZSwgb2JqZWN0c0tleVBhdHRlcm46IGFueSA9ICcqJykge1xuICAgIHJldHVybiB0aGlzLmdyYW50KGlkZW50aXR5LCBwZXJtcy5CVUNLRVRfREVMRVRFX0FDVElPTlMsIFtdLFxuICAgICAgdGhpcy5hcm5Gb3JPYmplY3RzKG9iamVjdHNLZXlQYXR0ZXJuKSk7XG4gIH1cblxuICBwdWJsaWMgZ3JhbnRSZWFkV3JpdGUoaWRlbnRpdHk6IGlhbS5JR3JhbnRhYmxlLCBvYmplY3RzS2V5UGF0dGVybjogYW55ID0gJyonKSB7XG4gICAgY29uc3QgYnVja2V0QWN0aW9ucyA9IHBlcm1zLkJVQ0tFVF9SRUFEX0FDVElPTlMuY29uY2F0KHRoaXMud3JpdGVBY3Rpb25zKTtcbiAgICAvLyB3ZSBuZWVkIHVuaXF1ZSBwZXJtaXNzaW9ucyBiZWNhdXNlIHNvbWUgcGVybWlzc2lvbnMgYXJlIGNvbW1vbiBiZXR3ZWVuIHJlYWQgYW5kIHdyaXRlIGtleSBhY3Rpb25zXG4gICAgY29uc3Qga2V5QWN0aW9ucyA9IFsuLi5uZXcgU2V0KFsuLi5wZXJtcy5LRVlfUkVBRF9BQ1RJT05TLCAuLi5wZXJtcy5LRVlfV1JJVEVfQUNUSU9OU10pXTtcblxuICAgIHJldHVybiB0aGlzLmdyYW50KGlkZW50aXR5LFxuICAgICAgYnVja2V0QWN0aW9ucyxcbiAgICAgIGtleUFjdGlvbnMsXG4gICAgICB0aGlzLmJ1Y2tldEFybixcbiAgICAgIHRoaXMuYXJuRm9yT2JqZWN0cyhvYmplY3RzS2V5UGF0dGVybikpO1xuICB9XG5cbiAgLyoqXG4gICAqIEFsbG93cyB1bnJlc3RyaWN0ZWQgYWNjZXNzIHRvIG9iamVjdHMgZnJvbSB0aGlzIGJ1Y2tldC5cbiAgICpcbiAgICogSU1QT1JUQU5UOiBUaGlzIHBlcm1pc3Npb24gYWxsb3dzIGFueW9uZSB0byBwZXJmb3JtIGFjdGlvbnMgb24gUzMgb2JqZWN0c1xuICAgKiBpbiB0aGlzIGJ1Y2tldCwgd2hpY2ggaXMgdXNlZnVsIGZvciB3aGVuIHlvdSBjb25maWd1cmUgeW91ciBidWNrZXQgYXMgYVxuICAgKiB3ZWJzaXRlIGFuZCB3YW50IGV2ZXJ5b25lIHRvIGJlIGFibGUgdG8gcmVhZCBvYmplY3RzIGluIHRoZSBidWNrZXQgd2l0aG91dFxuICAgKiBuZWVkaW5nIHRvIGF1dGhlbnRpY2F0ZS5cbiAgICpcbiAgICogV2l0aG91dCBhcmd1bWVudHMsIHRoaXMgbWV0aG9kIHdpbGwgZ3JhbnQgcmVhZCAoXCJzMzpHZXRPYmplY3RcIikgYWNjZXNzIHRvXG4gICAqIGFsbCBvYmplY3RzIChcIipcIikgaW4gdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogVGhlIG1ldGhvZCByZXR1cm5zIHRoZSBgaWFtLkdyYW50YCBvYmplY3QsIHdoaWNoIGNhbiB0aGVuIGJlIG1vZGlmaWVkXG4gICAqIGFzIG5lZWRlZC4gRm9yIGV4YW1wbGUsIHlvdSBjYW4gYWRkIGEgY29uZGl0aW9uIHRoYXQgd2lsbCByZXN0cmljdCBhY2Nlc3Mgb25seVxuICAgKiB0byBhbiBJUHY0IHJhbmdlIGxpa2UgdGhpczpcbiAgICpcbiAgICogICAgIGNvbnN0IGdyYW50ID0gYnVja2V0LmdyYW50UHVibGljQWNjZXNzKCk7XG4gICAqICAgICBncmFudC5yZXNvdXJjZVN0YXRlbWVudCEuYWRkQ29uZGl0aW9uKOKAmElwQWRkcmVzc+KAmSwgeyDigJxhd3M6U291cmNlSXDigJ06IOKAnDU0LjI0MC4xNDMuMC8yNOKAnSB9KTtcbiAgICpcbiAgICogTm90ZSB0aGF0IGlmIHRoaXMgYElCdWNrZXRgIHJlZmVycyB0byBhbiBleGlzdGluZyBidWNrZXQsIHBvc3NpYmx5IG5vdFxuICAgKiBtYW5hZ2VkIGJ5IENsb3VkRm9ybWF0aW9uLCB0aGlzIG1ldGhvZCB3aWxsIGhhdmUgbm8gZWZmZWN0LCBzaW5jZSBpdCdzXG4gICAqIGltcG9zc2libGUgdG8gbW9kaWZ5IHRoZSBwb2xpY3kgb2YgYW4gZXhpc3RpbmcgYnVja2V0LlxuICAgKlxuICAgKiBAcGFyYW0ga2V5UHJlZml4IHRoZSBwcmVmaXggb2YgUzMgb2JqZWN0IGtleXMgKGUuZy4gYGhvbWUvKmApLiBEZWZhdWx0IGlzIFwiKlwiLlxuICAgKiBAcGFyYW0gYWxsb3dlZEFjdGlvbnMgdGhlIHNldCBvZiBTMyBhY3Rpb25zIHRvIGFsbG93LiBEZWZhdWx0IGlzIFwiczM6R2V0T2JqZWN0XCIuXG4gICAqL1xuICBwdWJsaWMgZ3JhbnRQdWJsaWNBY2Nlc3Moa2V5UHJlZml4ID0gJyonLCAuLi5hbGxvd2VkQWN0aW9uczogc3RyaW5nW10pIHtcbiAgICBpZiAodGhpcy5kaXNhbGxvd1B1YmxpY0FjY2Vzcykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2Fubm90IGdyYW50IHB1YmxpYyBhY2Nlc3Mgd2hlbiAnYmxvY2tQdWJsaWNQb2xpY3knIGlzIGVuYWJsZWRcIik7XG4gICAgfVxuXG4gICAgYWxsb3dlZEFjdGlvbnMgPSBhbGxvd2VkQWN0aW9ucy5sZW5ndGggPiAwID8gYWxsb3dlZEFjdGlvbnMgOiBbJ3MzOkdldE9iamVjdCddO1xuXG4gICAgcmV0dXJuIGlhbS5HcmFudC5hZGRUb1ByaW5jaXBhbE9yUmVzb3VyY2Uoe1xuICAgICAgYWN0aW9uczogYWxsb3dlZEFjdGlvbnMsXG4gICAgICByZXNvdXJjZUFybnM6IFt0aGlzLmFybkZvck9iamVjdHMoa2V5UHJlZml4KV0sXG4gICAgICBncmFudGVlOiBuZXcgaWFtLkFueVByaW5jaXBhbCgpLFxuICAgICAgcmVzb3VyY2U6IHRoaXMsXG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQWRkcyBhIGJ1Y2tldCBub3RpZmljYXRpb24gZXZlbnQgZGVzdGluYXRpb24uXG4gICAqIEBwYXJhbSBldmVudCBUaGUgZXZlbnQgdG8gdHJpZ2dlciB0aGUgbm90aWZpY2F0aW9uXG4gICAqIEBwYXJhbSBkZXN0IFRoZSBub3RpZmljYXRpb24gZGVzdGluYXRpb24gKExhbWJkYSwgU05TIFRvcGljIG9yIFNRUyBRdWV1ZSlcbiAgICpcbiAgICogQHBhcmFtIGZpbHRlcnMgUzMgb2JqZWN0IGtleSBmaWx0ZXIgcnVsZXMgdG8gZGV0ZXJtaW5lIHdoaWNoIG9iamVjdHNcbiAgICogdHJpZ2dlciB0aGlzIGV2ZW50LiBFYWNoIGZpbHRlciBtdXN0IGluY2x1ZGUgYSBgcHJlZml4YCBhbmQvb3IgYHN1ZmZpeGBcbiAgICogdGhhdCB3aWxsIGJlIG1hdGNoZWQgYWdhaW5zdCB0aGUgczMgb2JqZWN0IGtleS4gUmVmZXIgdG8gdGhlIFMzIERldmVsb3BlciBHdWlkZVxuICAgKiBmb3IgZGV0YWlscyBhYm91dCBhbGxvd2VkIGZpbHRlciBydWxlcy5cbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9Ob3RpZmljYXRpb25Ib3dUby5odG1sI25vdGlmaWNhdGlvbi1ob3ctdG8tZmlsdGVyaW5nXG4gICAqXG4gICAqIEBleGFtcGxlXG4gICAqXG4gICAqICAgIGRlY2xhcmUgY29uc3QgbXlMYW1iZGE6IGxhbWJkYS5GdW5jdGlvbjtcbiAgICogICAgY29uc3QgYnVja2V0ID0gbmV3IHMzLkJ1Y2tldCh0aGlzLCAnTXlCdWNrZXQnKTtcbiAgICogICAgYnVja2V0LmFkZEV2ZW50Tm90aWZpY2F0aW9uKHMzLkV2ZW50VHlwZS5PQkpFQ1RfQ1JFQVRFRCwgbmV3IHMzbi5MYW1iZGFEZXN0aW5hdGlvbihteUxhbWJkYSksIHtwcmVmaXg6ICdob21lL215dXNlcm5hbWUvKid9KTtcbiAgICpcbiAgICogQHNlZVxuICAgKiBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9Ob3RpZmljYXRpb25Ib3dUby5odG1sXG4gICAqL1xuICBwdWJsaWMgYWRkRXZlbnROb3RpZmljYXRpb24oZXZlbnQ6IEV2ZW50VHlwZSwgZGVzdDogSUJ1Y2tldE5vdGlmaWNhdGlvbkRlc3RpbmF0aW9uLCAuLi5maWx0ZXJzOiBOb3RpZmljYXRpb25LZXlGaWx0ZXJbXSkge1xuICAgIHRoaXMud2l0aE5vdGlmaWNhdGlvbnMobm90aWZpY2F0aW9ucyA9PiBub3RpZmljYXRpb25zLmFkZE5vdGlmaWNhdGlvbihldmVudCwgZGVzdCwgLi4uZmlsdGVycykpO1xuICB9XG5cbiAgcHJpdmF0ZSB3aXRoTm90aWZpY2F0aW9ucyhjYjogKG5vdGlmaWNhdGlvbnM6IEJ1Y2tldE5vdGlmaWNhdGlvbnMpID0+IHZvaWQpIHtcbiAgICBpZiAoIXRoaXMubm90aWZpY2F0aW9ucykge1xuICAgICAgdGhpcy5ub3RpZmljYXRpb25zID0gbmV3IEJ1Y2tldE5vdGlmaWNhdGlvbnModGhpcywgJ05vdGlmaWNhdGlvbnMnLCB7XG4gICAgICAgIGJ1Y2tldDogdGhpcyxcbiAgICAgICAgaGFuZGxlclJvbGU6IHRoaXMubm90aWZpY2F0aW9uc0hhbmRsZXJSb2xlLFxuICAgICAgfSk7XG4gICAgfVxuICAgIGNiKHRoaXMubm90aWZpY2F0aW9ucyk7XG4gIH1cblxuICAvKipcbiAgICogU3Vic2NyaWJlcyBhIGRlc3RpbmF0aW9uIHRvIHJlY2VpdmUgbm90aWZpY2F0aW9ucyB3aGVuIGFuIG9iamVjdCBpc1xuICAgKiBjcmVhdGVkIGluIHRoZSBidWNrZXQuIFRoaXMgaXMgaWRlbnRpY2FsIHRvIGNhbGxpbmdcbiAgICogYG9uRXZlbnQoRXZlbnRUeXBlLk9CSkVDVF9DUkVBVEVEKWAuXG4gICAqXG4gICAqIEBwYXJhbSBkZXN0IFRoZSBub3RpZmljYXRpb24gZGVzdGluYXRpb24gKHNlZSBvbkV2ZW50KVxuICAgKiBAcGFyYW0gZmlsdGVycyBGaWx0ZXJzIChzZWUgb25FdmVudClcbiAgICovXG4gIHB1YmxpYyBhZGRPYmplY3RDcmVhdGVkTm90aWZpY2F0aW9uKGRlc3Q6IElCdWNrZXROb3RpZmljYXRpb25EZXN0aW5hdGlvbiwgLi4uZmlsdGVyczogTm90aWZpY2F0aW9uS2V5RmlsdGVyW10pIHtcbiAgICByZXR1cm4gdGhpcy5hZGRFdmVudE5vdGlmaWNhdGlvbihFdmVudFR5cGUuT0JKRUNUX0NSRUFURUQsIGRlc3QsIC4uLmZpbHRlcnMpO1xuICB9XG5cbiAgLyoqXG4gICAqIFN1YnNjcmliZXMgYSBkZXN0aW5hdGlvbiB0byByZWNlaXZlIG5vdGlmaWNhdGlvbnMgd2hlbiBhbiBvYmplY3QgaXNcbiAgICogcmVtb3ZlZCBmcm9tIHRoZSBidWNrZXQuIFRoaXMgaXMgaWRlbnRpY2FsIHRvIGNhbGxpbmdcbiAgICogYG9uRXZlbnQoRXZlbnRUeXBlLk9CSkVDVF9SRU1PVkVEKWAuXG4gICAqXG4gICAqIEBwYXJhbSBkZXN0IFRoZSBub3RpZmljYXRpb24gZGVzdGluYXRpb24gKHNlZSBvbkV2ZW50KVxuICAgKiBAcGFyYW0gZmlsdGVycyBGaWx0ZXJzIChzZWUgb25FdmVudClcbiAgICovXG4gIHB1YmxpYyBhZGRPYmplY3RSZW1vdmVkTm90aWZpY2F0aW9uKGRlc3Q6IElCdWNrZXROb3RpZmljYXRpb25EZXN0aW5hdGlvbiwgLi4uZmlsdGVyczogTm90aWZpY2F0aW9uS2V5RmlsdGVyW10pIHtcbiAgICByZXR1cm4gdGhpcy5hZGRFdmVudE5vdGlmaWNhdGlvbihFdmVudFR5cGUuT0JKRUNUX1JFTU9WRUQsIGRlc3QsIC4uLmZpbHRlcnMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEVuYWJsZXMgZXZlbnQgYnJpZGdlIG5vdGlmaWNhdGlvbiwgY2F1c2luZyBhbGwgZXZlbnRzIGJlbG93IHRvIGJlIHNlbnQgdG8gRXZlbnRCcmlkZ2U6XG4gICAqXG4gICAqIC0gT2JqZWN0IERlbGV0ZWQgKERlbGV0ZU9iamVjdClcbiAgICogLSBPYmplY3QgRGVsZXRlZCAoTGlmZWN5Y2xlIGV4cGlyYXRpb24pXG4gICAqIC0gT2JqZWN0IFJlc3RvcmUgSW5pdGlhdGVkXG4gICAqIC0gT2JqZWN0IFJlc3RvcmUgQ29tcGxldGVkXG4gICAqIC0gT2JqZWN0IFJlc3RvcmUgRXhwaXJlZFxuICAgKiAtIE9iamVjdCBTdG9yYWdlIENsYXNzIENoYW5nZWRcbiAgICogLSBPYmplY3QgQWNjZXNzIFRpZXIgQ2hhbmdlZFxuICAgKiAtIE9iamVjdCBBQ0wgVXBkYXRlZFxuICAgKiAtIE9iamVjdCBUYWdzIEFkZGVkXG4gICAqIC0gT2JqZWN0IFRhZ3MgRGVsZXRlZFxuICAgKi9cbiAgcHVibGljIGVuYWJsZUV2ZW50QnJpZGdlTm90aWZpY2F0aW9uKCkge1xuICAgIHRoaXMud2l0aE5vdGlmaWNhdGlvbnMobm90aWZpY2F0aW9ucyA9PiBub3RpZmljYXRpb25zLmVuYWJsZUV2ZW50QnJpZGdlTm90aWZpY2F0aW9uKCkpO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXQgd3JpdGVBY3Rpb25zKCk6IHN0cmluZ1tdIHtcbiAgICByZXR1cm4gW1xuICAgICAgLi4ucGVybXMuQlVDS0VUX0RFTEVURV9BQ1RJT05TLFxuICAgICAgLi4udGhpcy5wdXRBY3Rpb25zLFxuICAgIF07XG4gIH1cblxuICBwcml2YXRlIGdldCBwdXRBY3Rpb25zKCk6IHN0cmluZ1tdIHtcbiAgICByZXR1cm4gRmVhdHVyZUZsYWdzLm9mKHRoaXMpLmlzRW5hYmxlZChjeGFwaS5TM19HUkFOVF9XUklURV9XSVRIT1VUX0FDTClcbiAgICAgID8gcGVybXMuQlVDS0VUX1BVVF9BQ1RJT05TXG4gICAgICA6IHBlcm1zLkxFR0FDWV9CVUNLRVRfUFVUX0FDVElPTlM7XG4gIH1cblxuICBwcml2YXRlIHVybEpvaW4oLi4uY29tcG9uZW50czogc3RyaW5nW10pOiBzdHJpbmcge1xuICAgIHJldHVybiBjb21wb25lbnRzLnJlZHVjZSgocmVzdWx0LCBjb21wb25lbnQpID0+IHtcbiAgICAgIGlmIChyZXN1bHQuZW5kc1dpdGgoJy8nKSkge1xuICAgICAgICByZXN1bHQgPSByZXN1bHQuc2xpY2UoMCwgLTEpO1xuICAgICAgfVxuICAgICAgaWYgKGNvbXBvbmVudC5zdGFydHNXaXRoKCcvJykpIHtcbiAgICAgICAgY29tcG9uZW50ID0gY29tcG9uZW50LnNsaWNlKDEpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGAke3Jlc3VsdH0vJHtjb21wb25lbnR9YDtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgZ3JhbnQoXG4gICAgZ3JhbnRlZTogaWFtLklHcmFudGFibGUsXG4gICAgYnVja2V0QWN0aW9uczogc3RyaW5nW10sXG4gICAga2V5QWN0aW9uczogc3RyaW5nW10sXG4gICAgcmVzb3VyY2VBcm46IHN0cmluZywgLi4ub3RoZXJSZXNvdXJjZUFybnM6IHN0cmluZ1tdKSB7XG4gICAgY29uc3QgcmVzb3VyY2VzID0gW3Jlc291cmNlQXJuLCAuLi5vdGhlclJlc291cmNlQXJuc107XG5cbiAgICBjb25zdCByZXQgPSBpYW0uR3JhbnQuYWRkVG9QcmluY2lwYWxPclJlc291cmNlKHtcbiAgICAgIGdyYW50ZWUsXG4gICAgICBhY3Rpb25zOiBidWNrZXRBY3Rpb25zLFxuICAgICAgcmVzb3VyY2VBcm5zOiByZXNvdXJjZXMsXG4gICAgICByZXNvdXJjZTogdGhpcyxcbiAgICB9KTtcblxuICAgIGlmICh0aGlzLmVuY3J5cHRpb25LZXkgJiYga2V5QWN0aW9ucyAmJiBrZXlBY3Rpb25zLmxlbmd0aCAhPT0gMCkge1xuICAgICAgdGhpcy5lbmNyeXB0aW9uS2V5LmdyYW50KGdyYW50ZWUsIC4uLmtleUFjdGlvbnMpO1xuICAgIH1cblxuICAgIHJldHVybiByZXQ7XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBCbG9ja1B1YmxpY0FjY2Vzc09wdGlvbnMge1xuICAvKipcbiAgICogV2hldGhlciB0byBibG9jayBwdWJsaWMgQUNMc1xuICAgKlxuICAgKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25TMy9sYXRlc3QvZGV2L2FjY2Vzcy1jb250cm9sLWJsb2NrLXB1YmxpYy1hY2Nlc3MuaHRtbCNhY2Nlc3MtY29udHJvbC1ibG9jay1wdWJsaWMtYWNjZXNzLW9wdGlvbnNcbiAgICovXG4gIHJlYWRvbmx5IGJsb2NrUHVibGljQWNscz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gYmxvY2sgcHVibGljIHBvbGljeVxuICAgKlxuICAgKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25TMy9sYXRlc3QvZGV2L2FjY2Vzcy1jb250cm9sLWJsb2NrLXB1YmxpYy1hY2Nlc3MuaHRtbCNhY2Nlc3MtY29udHJvbC1ibG9jay1wdWJsaWMtYWNjZXNzLW9wdGlvbnNcbiAgICovXG4gIHJlYWRvbmx5IGJsb2NrUHVibGljUG9saWN5PzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hldGhlciB0byBpZ25vcmUgcHVibGljIEFDTHNcbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9hY2Nlc3MtY29udHJvbC1ibG9jay1wdWJsaWMtYWNjZXNzLmh0bWwjYWNjZXNzLWNvbnRyb2wtYmxvY2stcHVibGljLWFjY2Vzcy1vcHRpb25zXG4gICAqL1xuICByZWFkb25seSBpZ25vcmVQdWJsaWNBY2xzPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hldGhlciB0byByZXN0cmljdCBwdWJsaWMgYWNjZXNzXG4gICAqXG4gICAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvYWNjZXNzLWNvbnRyb2wtYmxvY2stcHVibGljLWFjY2Vzcy5odG1sI2FjY2Vzcy1jb250cm9sLWJsb2NrLXB1YmxpYy1hY2Nlc3Mtb3B0aW9uc1xuICAgKi9cbiAgcmVhZG9ubHkgcmVzdHJpY3RQdWJsaWNCdWNrZXRzPzogYm9vbGVhbjtcbn1cblxuZXhwb3J0IGNsYXNzIEJsb2NrUHVibGljQWNjZXNzIHtcbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBCTE9DS19BTEwgPSBuZXcgQmxvY2tQdWJsaWNBY2Nlc3Moe1xuICAgIGJsb2NrUHVibGljQWNsczogdHJ1ZSxcbiAgICBibG9ja1B1YmxpY1BvbGljeTogdHJ1ZSxcbiAgICBpZ25vcmVQdWJsaWNBY2xzOiB0cnVlLFxuICAgIHJlc3RyaWN0UHVibGljQnVja2V0czogdHJ1ZSxcbiAgfSk7XG5cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBCTE9DS19BQ0xTID0gbmV3IEJsb2NrUHVibGljQWNjZXNzKHtcbiAgICBibG9ja1B1YmxpY0FjbHM6IHRydWUsXG4gICAgaWdub3JlUHVibGljQWNsczogdHJ1ZSxcbiAgfSk7XG5cbiAgcHVibGljIGJsb2NrUHVibGljQWNsczogYm9vbGVhbiB8IHVuZGVmaW5lZDtcbiAgcHVibGljIGJsb2NrUHVibGljUG9saWN5OiBib29sZWFuIHwgdW5kZWZpbmVkO1xuICBwdWJsaWMgaWdub3JlUHVibGljQWNsczogYm9vbGVhbiB8IHVuZGVmaW5lZDtcbiAgcHVibGljIHJlc3RyaWN0UHVibGljQnVja2V0czogYm9vbGVhbiB8IHVuZGVmaW5lZDtcblxuICBjb25zdHJ1Y3RvcihvcHRpb25zOiBCbG9ja1B1YmxpY0FjY2Vzc09wdGlvbnMpIHtcbiAgICB0aGlzLmJsb2NrUHVibGljQWNscyA9IG9wdGlvbnMuYmxvY2tQdWJsaWNBY2xzO1xuICAgIHRoaXMuYmxvY2tQdWJsaWNQb2xpY3kgPSBvcHRpb25zLmJsb2NrUHVibGljUG9saWN5O1xuICAgIHRoaXMuaWdub3JlUHVibGljQWNscyA9IG9wdGlvbnMuaWdub3JlUHVibGljQWNscztcbiAgICB0aGlzLnJlc3RyaWN0UHVibGljQnVja2V0cyA9IG9wdGlvbnMucmVzdHJpY3RQdWJsaWNCdWNrZXRzO1xuICB9XG59XG5cbi8qKlxuICogU3BlY2lmaWVzIGEgbWV0cmljcyBjb25maWd1cmF0aW9uIGZvciB0aGUgQ2xvdWRXYXRjaCByZXF1ZXN0IG1ldHJpY3MgZnJvbSBhbiBBbWF6b24gUzMgYnVja2V0LlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEJ1Y2tldE1ldHJpY3Mge1xuICAvKipcbiAgICogVGhlIElEIHVzZWQgdG8gaWRlbnRpZnkgdGhlIG1ldHJpY3MgY29uZmlndXJhdGlvbi5cbiAgICovXG4gIHJlYWRvbmx5IGlkOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgcHJlZml4IHRoYXQgYW4gb2JqZWN0IG11c3QgaGF2ZSB0byBiZSBpbmNsdWRlZCBpbiB0aGUgbWV0cmljcyByZXN1bHRzLlxuICAgKi9cbiAgcmVhZG9ubHkgcHJlZml4Pzogc3RyaW5nO1xuICAvKipcbiAgICogU3BlY2lmaWVzIGEgbGlzdCBvZiB0YWcgZmlsdGVycyB0byB1c2UgYXMgYSBtZXRyaWNzIGNvbmZpZ3VyYXRpb24gZmlsdGVyLlxuICAgKiBUaGUgbWV0cmljcyBjb25maWd1cmF0aW9uIGluY2x1ZGVzIG9ubHkgb2JqZWN0cyB0aGF0IG1lZXQgdGhlIGZpbHRlcidzIGNyaXRlcmlhLlxuICAgKi9cbiAgcmVhZG9ubHkgdGFnRmlsdGVycz86IHsgW3RhZzogc3RyaW5nXTogYW55IH07XG59XG5cbi8qKlxuICogQWxsIGh0dHAgcmVxdWVzdCBtZXRob2RzXG4gKi9cbmV4cG9ydCBlbnVtIEh0dHBNZXRob2RzIHtcbiAgLyoqXG4gICAqIFRoZSBHRVQgbWV0aG9kIHJlcXVlc3RzIGEgcmVwcmVzZW50YXRpb24gb2YgdGhlIHNwZWNpZmllZCByZXNvdXJjZS5cbiAgICovXG4gIEdFVCA9ICdHRVQnLFxuICAvKipcbiAgICogVGhlIFBVVCBtZXRob2QgcmVwbGFjZXMgYWxsIGN1cnJlbnQgcmVwcmVzZW50YXRpb25zIG9mIHRoZSB0YXJnZXQgcmVzb3VyY2Ugd2l0aCB0aGUgcmVxdWVzdCBwYXlsb2FkLlxuICAgKi9cbiAgUFVUID0gJ1BVVCcsXG4gIC8qKlxuICAgKiBUaGUgSEVBRCBtZXRob2QgYXNrcyBmb3IgYSByZXNwb25zZSBpZGVudGljYWwgdG8gdGhhdCBvZiBhIEdFVCByZXF1ZXN0LCBidXQgd2l0aG91dCB0aGUgcmVzcG9uc2UgYm9keS5cbiAgICovXG4gIEhFQUQgPSAnSEVBRCcsXG4gIC8qKlxuICAgKiBUaGUgUE9TVCBtZXRob2QgaXMgdXNlZCB0byBzdWJtaXQgYW4gZW50aXR5IHRvIHRoZSBzcGVjaWZpZWQgcmVzb3VyY2UsIG9mdGVuIGNhdXNpbmcgYSBjaGFuZ2UgaW4gc3RhdGUgb3Igc2lkZSBlZmZlY3RzIG9uIHRoZSBzZXJ2ZXIuXG4gICAqL1xuICBQT1NUID0gJ1BPU1QnLFxuICAvKipcbiAgICogVGhlIERFTEVURSBtZXRob2QgZGVsZXRlcyB0aGUgc3BlY2lmaWVkIHJlc291cmNlLlxuICAgKi9cbiAgREVMRVRFID0gJ0RFTEVURScsXG59XG5cbi8qKlxuICogU3BlY2lmaWVzIGEgY3Jvc3Mtb3JpZ2luIGFjY2VzcyBydWxlIGZvciBhbiBBbWF6b24gUzMgYnVja2V0LlxuICovXG5leHBvcnQgaW50ZXJmYWNlIENvcnNSdWxlIHtcbiAgLyoqXG4gICAqIEEgdW5pcXVlIGlkZW50aWZpZXIgZm9yIHRoaXMgcnVsZS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBpZCBzcGVjaWZpZWQuXG4gICAqL1xuICByZWFkb25seSBpZD86IHN0cmluZztcbiAgLyoqXG4gICAqIFRoZSB0aW1lIGluIHNlY29uZHMgdGhhdCB5b3VyIGJyb3dzZXIgaXMgdG8gY2FjaGUgdGhlIHByZWZsaWdodCByZXNwb25zZSBmb3IgdGhlIHNwZWNpZmllZCByZXNvdXJjZS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBjYWNoaW5nLlxuICAgKi9cbiAgcmVhZG9ubHkgbWF4QWdlPzogbnVtYmVyO1xuICAvKipcbiAgICogSGVhZGVycyB0aGF0IGFyZSBzcGVjaWZpZWQgaW4gdGhlIEFjY2Vzcy1Db250cm9sLVJlcXVlc3QtSGVhZGVycyBoZWFkZXIuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gaGVhZGVycyBhbGxvd2VkLlxuICAgKi9cbiAgcmVhZG9ubHkgYWxsb3dlZEhlYWRlcnM/OiBzdHJpbmdbXTtcbiAgLyoqXG4gICAqIEFuIEhUVFAgbWV0aG9kIHRoYXQgeW91IGFsbG93IHRoZSBvcmlnaW4gdG8gZXhlY3V0ZS5cbiAgICovXG4gIHJlYWRvbmx5IGFsbG93ZWRNZXRob2RzOiBIdHRwTWV0aG9kc1tdO1xuICAvKipcbiAgICogT25lIG9yIG1vcmUgb3JpZ2lucyB5b3Ugd2FudCBjdXN0b21lcnMgdG8gYmUgYWJsZSB0byBhY2Nlc3MgdGhlIGJ1Y2tldCBmcm9tLlxuICAgKi9cbiAgcmVhZG9ubHkgYWxsb3dlZE9yaWdpbnM6IHN0cmluZ1tdO1xuICAvKipcbiAgICogT25lIG9yIG1vcmUgaGVhZGVycyBpbiB0aGUgcmVzcG9uc2UgdGhhdCB5b3Ugd2FudCBjdXN0b21lcnMgdG8gYmUgYWJsZSB0byBhY2Nlc3MgZnJvbSB0aGVpciBhcHBsaWNhdGlvbnMuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gaGVhZGVycyBleHBvc2VkLlxuICAgKi9cbiAgcmVhZG9ubHkgZXhwb3NlZEhlYWRlcnM/OiBzdHJpbmdbXTtcbn1cblxuLyoqXG4gKiBBbGwgaHR0cCByZXF1ZXN0IG1ldGhvZHNcbiAqL1xuZXhwb3J0IGVudW0gUmVkaXJlY3RQcm90b2NvbCB7XG4gIEhUVFAgPSAnaHR0cCcsXG4gIEhUVFBTID0gJ2h0dHBzJyxcbn1cblxuLyoqXG4gKiBTcGVjaWZpZXMgYSByZWRpcmVjdCBiZWhhdmlvciBvZiBhbGwgcmVxdWVzdHMgdG8gYSB3ZWJzaXRlIGVuZHBvaW50IG9mIGEgYnVja2V0LlxuICovXG5leHBvcnQgaW50ZXJmYWNlIFJlZGlyZWN0VGFyZ2V0IHtcbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIGhvc3Qgd2hlcmUgcmVxdWVzdHMgYXJlIHJlZGlyZWN0ZWRcbiAgICovXG4gIHJlYWRvbmx5IGhvc3ROYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFByb3RvY29sIHRvIHVzZSB3aGVuIHJlZGlyZWN0aW5nIHJlcXVlc3RzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVGhlIHByb3RvY29sIHVzZWQgaW4gdGhlIG9yaWdpbmFsIHJlcXVlc3QuXG4gICAqL1xuICByZWFkb25seSBwcm90b2NvbD86IFJlZGlyZWN0UHJvdG9jb2w7XG59XG5cbi8qKlxuICogQWxsIHN1cHBvcnRlZCBpbnZlbnRvcnkgbGlzdCBmb3JtYXRzLlxuICovXG5leHBvcnQgZW51bSBJbnZlbnRvcnlGb3JtYXQge1xuICAvKipcbiAgICogR2VuZXJhdGUgdGhlIGludmVudG9yeSBsaXN0IGFzIENTVi5cbiAgICovXG4gIENTViA9ICdDU1YnLFxuICAvKipcbiAgICogR2VuZXJhdGUgdGhlIGludmVudG9yeSBsaXN0IGFzIFBhcnF1ZXQuXG4gICAqL1xuICBQQVJRVUVUID0gJ1BhcnF1ZXQnLFxuICAvKipcbiAgICogR2VuZXJhdGUgdGhlIGludmVudG9yeSBsaXN0IGFzIE9SQy5cbiAgICovXG4gIE9SQyA9ICdPUkMnLFxufVxuXG4vKipcbiAqIEFsbCBzdXBwb3J0ZWQgaW52ZW50b3J5IGZyZXF1ZW5jaWVzLlxuICovXG5leHBvcnQgZW51bSBJbnZlbnRvcnlGcmVxdWVuY3kge1xuICAvKipcbiAgICogQSByZXBvcnQgaXMgZ2VuZXJhdGVkIGV2ZXJ5IGRheS5cbiAgICovXG4gIERBSUxZID0gJ0RhaWx5JyxcbiAgLyoqXG4gICAqIEEgcmVwb3J0IGlzIGdlbmVyYXRlZCBldmVyeSBTdW5kYXkgKFVUQyB0aW1lem9uZSkgYWZ0ZXIgdGhlIGluaXRpYWwgcmVwb3J0LlxuICAgKi9cbiAgV0VFS0xZID0gJ1dlZWtseSdcbn1cblxuLyoqXG4gKiBJbnZlbnRvcnkgdmVyc2lvbiBzdXBwb3J0LlxuICovXG5leHBvcnQgZW51bSBJbnZlbnRvcnlPYmplY3RWZXJzaW9uIHtcbiAgLyoqXG4gICAqIEluY2x1ZGVzIGFsbCB2ZXJzaW9ucyBvZiBlYWNoIG9iamVjdCBpbiB0aGUgcmVwb3J0LlxuICAgKi9cbiAgQUxMID0gJ0FsbCcsXG4gIC8qKlxuICAgKiBJbmNsdWRlcyBvbmx5IHRoZSBjdXJyZW50IHZlcnNpb24gb2YgZWFjaCBvYmplY3QgaW4gdGhlIHJlcG9ydC5cbiAgICovXG4gIENVUlJFTlQgPSAnQ3VycmVudCcsXG59XG5cbi8qKlxuICogVGhlIGRlc3RpbmF0aW9uIG9mIHRoZSBpbnZlbnRvcnkuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSW52ZW50b3J5RGVzdGluYXRpb24ge1xuICAvKipcbiAgICogQnVja2V0IHdoZXJlIGFsbCBpbnZlbnRvcmllcyB3aWxsIGJlIHNhdmVkIGluLlxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0OiBJQnVja2V0O1xuICAvKipcbiAgICogVGhlIHByZWZpeCB0byBiZSB1c2VkIHdoZW4gc2F2aW5nIHRoZSBpbnZlbnRvcnkuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gcHJlZml4LlxuICAgKi9cbiAgcmVhZG9ubHkgcHJlZml4Pzogc3RyaW5nO1xuICAvKipcbiAgICogVGhlIGFjY291bnQgSUQgdGhhdCBvd25zIHRoZSBkZXN0aW5hdGlvbiBTMyBidWNrZXQuXG4gICAqIElmIG5vIGFjY291bnQgSUQgaXMgcHJvdmlkZWQsIHRoZSBvd25lciBpcyBub3QgdmFsaWRhdGVkIGJlZm9yZSBleHBvcnRpbmcgZGF0YS5cbiAgICogSXQncyByZWNvbW1lbmRlZCB0byBzZXQgYW4gYWNjb3VudCBJRCB0byBwcmV2ZW50IHByb2JsZW1zIGlmIHRoZSBkZXN0aW5hdGlvbiBidWNrZXQgb3duZXJzaGlwIGNoYW5nZXMuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gYWNjb3VudCBJRC5cbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldE93bmVyPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIFNwZWNpZmllcyB0aGUgaW52ZW50b3J5IGNvbmZpZ3VyYXRpb24gb2YgYW4gUzMgQnVja2V0LlxuICpcbiAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvc3RvcmFnZS1pbnZlbnRvcnkuaHRtbFxuICovXG5leHBvcnQgaW50ZXJmYWNlIEludmVudG9yeSB7XG4gIC8qKlxuICAgKiBUaGUgZGVzdGluYXRpb24gb2YgdGhlIGludmVudG9yeS5cbiAgICovXG4gIHJlYWRvbmx5IGRlc3RpbmF0aW9uOiBJbnZlbnRvcnlEZXN0aW5hdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBpbnZlbnRvcnkgd2lsbCBvbmx5IGluY2x1ZGUgb2JqZWN0cyB0aGF0IG1lZXQgdGhlIHByZWZpeCBmaWx0ZXIgY3JpdGVyaWEuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gb2JqZWN0cyBwcmVmaXhcbiAgICovXG4gIHJlYWRvbmx5IG9iamVjdHNQcmVmaXg/OiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgZm9ybWF0IG9mIHRoZSBpbnZlbnRvcnkuXG4gICAqXG4gICAqIEBkZWZhdWx0IEludmVudG9yeUZvcm1hdC5DU1ZcbiAgICovXG4gIHJlYWRvbmx5IGZvcm1hdD86IEludmVudG9yeUZvcm1hdDtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdGhlIGludmVudG9yeSBpcyBlbmFibGVkIG9yIGRpc2FibGVkLlxuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICByZWFkb25seSBlbmFibGVkPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIFRoZSBpbnZlbnRvcnkgY29uZmlndXJhdGlvbiBJRC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBnZW5lcmF0ZWQgSUQuXG4gICAqL1xuICByZWFkb25seSBpbnZlbnRvcnlJZD86IHN0cmluZztcbiAgLyoqXG4gICAqIEZyZXF1ZW5jeSBhdCB3aGljaCB0aGUgaW52ZW50b3J5IHNob3VsZCBiZSBnZW5lcmF0ZWQuXG4gICAqXG4gICAqIEBkZWZhdWx0IEludmVudG9yeUZyZXF1ZW5jeS5XRUVLTFlcbiAgICovXG4gIHJlYWRvbmx5IGZyZXF1ZW5jeT86IEludmVudG9yeUZyZXF1ZW5jeTtcbiAgLyoqXG4gICAqIElmIHRoZSBpbnZlbnRvcnkgc2hvdWxkIGNvbnRhaW4gYWxsIHRoZSBvYmplY3QgdmVyc2lvbnMgb3Igb25seSB0aGUgY3VycmVudCBvbmUuXG4gICAqXG4gICAqIEBkZWZhdWx0IEludmVudG9yeU9iamVjdFZlcnNpb24uQUxMXG4gICAqL1xuICByZWFkb25seSBpbmNsdWRlT2JqZWN0VmVyc2lvbnM/OiBJbnZlbnRvcnlPYmplY3RWZXJzaW9uO1xuICAvKipcbiAgICogQSBsaXN0IG9mIG9wdGlvbmFsIGZpZWxkcyB0byBiZSBpbmNsdWRlZCBpbiB0aGUgaW52ZW50b3J5IHJlc3VsdC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBvcHRpb25hbCBmaWVsZHMuXG4gICAqL1xuICByZWFkb25seSBvcHRpb25hbEZpZWxkcz86IHN0cmluZ1tdO1xufVxuLyoqXG4gICAqIFRoZSBPYmplY3RPd25lcnNoaXAgb2YgdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9hYm91dC1vYmplY3Qtb3duZXJzaGlwLmh0bWxcbiAgICpcbiAgICovXG5leHBvcnQgZW51bSBPYmplY3RPd25lcnNoaXAge1xuICAvKipcbiAgICogQUNMcyBhcmUgZGlzYWJsZWQsIGFuZCB0aGUgYnVja2V0IG93bmVyIGF1dG9tYXRpY2FsbHkgb3duc1xuICAgKiBhbmQgaGFzIGZ1bGwgY29udHJvbCBvdmVyIGV2ZXJ5IG9iamVjdCBpbiB0aGUgYnVja2V0LlxuICAgKiBBQ0xzIG5vIGxvbmdlciBhZmZlY3QgcGVybWlzc2lvbnMgdG8gZGF0YSBpbiB0aGUgUzMgYnVja2V0LlxuICAgKiBUaGUgYnVja2V0IHVzZXMgcG9saWNpZXMgdG8gZGVmaW5lIGFjY2VzcyBjb250cm9sLlxuICAgKi9cbiAgQlVDS0VUX09XTkVSX0VORk9SQ0VEID0gJ0J1Y2tldE93bmVyRW5mb3JjZWQnLFxuICAvKipcbiAgICogT2JqZWN0cyB1cGxvYWRlZCB0byB0aGUgYnVja2V0IGNoYW5nZSBvd25lcnNoaXAgdG8gdGhlIGJ1Y2tldCBvd25lciAuXG4gICAqL1xuICBCVUNLRVRfT1dORVJfUFJFRkVSUkVEID0gJ0J1Y2tldE93bmVyUHJlZmVycmVkJyxcbiAgLyoqXG4gICAqIFRoZSB1cGxvYWRpbmcgYWNjb3VudCB3aWxsIG93biB0aGUgb2JqZWN0LlxuICAgKi9cbiAgT0JKRUNUX1dSSVRFUiA9ICdPYmplY3RXcml0ZXInLFxufVxuLyoqXG4gKiBUaGUgaW50ZWxsaWdlbnQgdGllcmluZyBjb25maWd1cmF0aW9uLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEludGVsbGlnZW50VGllcmluZ0NvbmZpZ3VyYXRpb24ge1xuICAvKipcbiAgICogQ29uZmlndXJhdGlvbiBuYW1lXG4gICAqL1xuICByZWFkb25seSBuYW1lOiBzdHJpbmc7XG5cblxuICAvKipcbiAgICogQWRkIGEgZmlsdGVyIHRvIGxpbWl0IHRoZSBzY29wZSBvZiB0aGlzIGNvbmZpZ3VyYXRpb24gdG8gYSBzaW5nbGUgcHJlZml4LlxuICAgKlxuICAgKiBAZGVmYXVsdCB0aGlzIGNvbmZpZ3VyYXRpb24gd2lsbCBhcHBseSB0byAqKmFsbCoqIG9iamVjdHMgaW4gdGhlIGJ1Y2tldC5cbiAgICovXG4gIHJlYWRvbmx5IHByZWZpeD86IHN0cmluZztcblxuICAvKipcbiAgICogWW91IGNhbiBsaW1pdCB0aGUgc2NvcGUgb2YgdGhpcyBydWxlIHRvIHRoZSBrZXkgdmFsdWUgcGFpcnMgYWRkZWQgYmVsb3cuXG4gICAqXG4gICAqIEBkZWZhdWx0IE5vIGZpbHRlcmluZyB3aWxsIGJlIHBlcmZvcm1lZCBvbiB0YWdzXG4gICAqL1xuICByZWFkb25seSB0YWdzPzogVGFnW107XG5cbiAgLyoqXG4gICAqIFdoZW4gZW5hYmxlZCwgSW50ZWxsaWdlbnQtVGllcmluZyB3aWxsIGF1dG9tYXRpY2FsbHkgbW92ZSBvYmplY3RzIHRoYXRcbiAgICogaGF2ZW7igJl0IGJlZW4gYWNjZXNzZWQgZm9yIGEgbWluaW11bSBvZiA5MCBkYXlzIHRvIHRoZSBBcmNoaXZlIEFjY2VzcyB0aWVyLlxuICAgKlxuICAgKiBAZGVmYXVsdCBPYmplY3RzIHdpbGwgbm90IG1vdmUgdG8gR2xhY2llclxuICAgKi9cbiAgcmVhZG9ubHkgYXJjaGl2ZUFjY2Vzc1RpZXJUaW1lPzogRHVyYXRpb247XG5cbiAgLyoqXG4gICAqIFdoZW4gZW5hYmxlZCwgSW50ZWxsaWdlbnQtVGllcmluZyB3aWxsIGF1dG9tYXRpY2FsbHkgbW92ZSBvYmplY3RzIHRoYXRcbiAgICogaGF2ZW7igJl0IGJlZW4gYWNjZXNzZWQgZm9yIGEgbWluaW11bSBvZiAxODAgZGF5cyB0byB0aGUgRGVlcCBBcmNoaXZlIEFjY2Vzc1xuICAgKiB0aWVyLlxuICAgKlxuICAgKiBAZGVmYXVsdCBPYmplY3RzIHdpbGwgbm90IG1vdmUgdG8gR2xhY2llciBEZWVwIEFjY2Vzc1xuICAgKi9cbiAgcmVhZG9ubHkgZGVlcEFyY2hpdmVBY2Nlc3NUaWVyVGltZT86IER1cmF0aW9uO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1Y2tldFByb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBraW5kIG9mIHNlcnZlci1zaWRlIGVuY3J5cHRpb24gdG8gYXBwbHkgdG8gdGhpcyBidWNrZXQuXG4gICAqXG4gICAqIElmIHlvdSBjaG9vc2UgS01TLCB5b3UgY2FuIHNwZWNpZnkgYSBLTVMga2V5IHZpYSBgZW5jcnlwdGlvbktleWAuIElmXG4gICAqIGVuY3J5cHRpb24ga2V5IGlzIG5vdCBzcGVjaWZpZWQsIGEga2V5IHdpbGwgYXV0b21hdGljYWxseSBiZSBjcmVhdGVkLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIGBLbXNgIGlmIGBlbmNyeXB0aW9uS2V5YCBpcyBzcGVjaWZpZWQsIG9yIGBVbmVuY3J5cHRlZGAgb3RoZXJ3aXNlLlxuICAgKi9cbiAgcmVhZG9ubHkgZW5jcnlwdGlvbj86IEJ1Y2tldEVuY3J5cHRpb247XG5cbiAgLyoqXG4gICAqIEV4dGVybmFsIEtNUyBrZXkgdG8gdXNlIGZvciBidWNrZXQgZW5jcnlwdGlvbi5cbiAgICpcbiAgICogVGhlICdlbmNyeXB0aW9uJyBwcm9wZXJ0eSBtdXN0IGJlIGVpdGhlciBub3Qgc3BlY2lmaWVkIG9yIHNldCB0byBcIkttc1wiLlxuICAgKiBBbiBlcnJvciB3aWxsIGJlIGVtaXR0ZWQgaWYgZW5jcnlwdGlvbiBpcyBzZXQgdG8gXCJVbmVuY3J5cHRlZFwiIG9yXG4gICAqIFwiTWFuYWdlZFwiLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIElmIGVuY3J5cHRpb24gaXMgc2V0IHRvIFwiS21zXCIgYW5kIHRoaXMgcHJvcGVydHkgaXMgdW5kZWZpbmVkLFxuICAgKiBhIG5ldyBLTVMga2V5IHdpbGwgYmUgY3JlYXRlZCBhbmQgYXNzb2NpYXRlZCB3aXRoIHRoaXMgYnVja2V0LlxuICAgKi9cbiAgcmVhZG9ubHkgZW5jcnlwdGlvbktleT86IGttcy5JS2V5O1xuXG4gIC8qKlxuICAqIEVuZm9yY2VzIFNTTCBmb3IgcmVxdWVzdHMuIFMzLjUgb2YgdGhlIEFXUyBGb3VuZGF0aW9uYWwgU2VjdXJpdHkgQmVzdCBQcmFjdGljZXMgUmVnYXJkaW5nIFMzLlxuICAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL2NvbmZpZy9sYXRlc3QvZGV2ZWxvcGVyZ3VpZGUvczMtYnVja2V0LXNzbC1yZXF1ZXN0cy1vbmx5Lmh0bWxcbiAgKlxuICAqIEBkZWZhdWx0IGZhbHNlXG4gICovXG4gIHJlYWRvbmx5IGVuZm9yY2VTU0w/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBTcGVjaWZpZXMgd2hldGhlciBBbWF6b24gUzMgc2hvdWxkIHVzZSBhbiBTMyBCdWNrZXQgS2V5IHdpdGggc2VydmVyLXNpZGVcbiAgICogZW5jcnlwdGlvbiB1c2luZyBLTVMgKFNTRS1LTVMpIGZvciBuZXcgb2JqZWN0cyBpbiB0aGUgYnVja2V0LlxuICAgKlxuICAgKiBPbmx5IHJlbGV2YW50LCB3aGVuIEVuY3J5cHRpb24gaXMgc2V0IHRvIHtAbGluayBCdWNrZXRFbmNyeXB0aW9uLktNU31cbiAgICpcbiAgICogQGRlZmF1bHQgLSBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYnVja2V0S2V5RW5hYmxlZD86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFBoeXNpY2FsIG5hbWUgb2YgdGhpcyBidWNrZXQuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gQXNzaWduZWQgYnkgQ2xvdWRGb3JtYXRpb24gKHJlY29tbWVuZGVkKS5cbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldE5hbWU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFBvbGljeSB0byBhcHBseSB3aGVuIHRoZSBidWNrZXQgaXMgcmVtb3ZlZCBmcm9tIHRoaXMgc3RhY2suXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVGhlIGJ1Y2tldCB3aWxsIGJlIG9ycGhhbmVkLlxuICAgKi9cbiAgcmVhZG9ubHkgcmVtb3ZhbFBvbGljeT86IFJlbW92YWxQb2xpY3k7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgYWxsIG9iamVjdHMgc2hvdWxkIGJlIGF1dG9tYXRpY2FsbHkgZGVsZXRlZCB3aGVuIHRoZSBidWNrZXQgaXNcbiAgICogcmVtb3ZlZCBmcm9tIHRoZSBzdGFjayBvciB3aGVuIHRoZSBzdGFjayBpcyBkZWxldGVkLlxuICAgKlxuICAgKiBSZXF1aXJlcyB0aGUgYHJlbW92YWxQb2xpY3lgIHRvIGJlIHNldCB0byBgUmVtb3ZhbFBvbGljeS5ERVNUUk9ZYC5cbiAgICpcbiAgICogKipXYXJuaW5nKiogaWYgeW91IGhhdmUgZGVwbG95ZWQgYSBidWNrZXQgd2l0aCBgYXV0b0RlbGV0ZU9iamVjdHM6IHRydWVgLFxuICAgKiBzd2l0Y2hpbmcgdGhpcyB0byBgZmFsc2VgIGluIGEgQ0RLIHZlcnNpb24gKmJlZm9yZSogYDEuMTI2LjBgIHdpbGwgbGVhZCB0b1xuICAgKiBhbGwgb2JqZWN0cyBpbiB0aGUgYnVja2V0IGJlaW5nIGRlbGV0ZWQuIEJlIHN1cmUgdG8gdXBkYXRlIHlvdXIgYnVja2V0IHJlc291cmNlc1xuICAgKiBieSBkZXBsb3lpbmcgd2l0aCBDREsgdmVyc2lvbiBgMS4xMjYuMGAgb3IgbGF0ZXIgKipiZWZvcmUqKiBzd2l0Y2hpbmcgdGhpcyB2YWx1ZSB0byBgZmFsc2VgLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXV0b0RlbGV0ZU9iamVjdHM/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRoaXMgYnVja2V0IHNob3VsZCBoYXZlIHZlcnNpb25pbmcgdHVybmVkIG9uIG9yIG5vdC5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IHZlcnNpb25lZD86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdGhpcyBidWNrZXQgc2hvdWxkIHNlbmQgbm90aWZpY2F0aW9ucyB0byBBbWF6b24gRXZlbnRCcmlkZ2Ugb3Igbm90LlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgZXZlbnRCcmlkZ2VFbmFibGVkPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogUnVsZXMgdGhhdCBkZWZpbmUgaG93IEFtYXpvbiBTMyBtYW5hZ2VzIG9iamVjdHMgZHVyaW5nIHRoZWlyIGxpZmV0aW1lLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE5vIGxpZmVjeWNsZSBydWxlcy5cbiAgICovXG4gIHJlYWRvbmx5IGxpZmVjeWNsZVJ1bGVzPzogTGlmZWN5Y2xlUnVsZVtdO1xuXG4gIC8qKlxuICAgKiBUaGUgbmFtZSBvZiB0aGUgaW5kZXggZG9jdW1lbnQgKGUuZy4gXCJpbmRleC5odG1sXCIpIGZvciB0aGUgd2Vic2l0ZS4gRW5hYmxlcyBzdGF0aWMgd2Vic2l0ZVxuICAgKiBob3N0aW5nIGZvciB0aGlzIGJ1Y2tldC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBpbmRleCBkb2N1bWVudC5cbiAgICovXG4gIHJlYWRvbmx5IHdlYnNpdGVJbmRleERvY3VtZW50Pzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgbmFtZSBvZiB0aGUgZXJyb3IgZG9jdW1lbnQgKGUuZy4gXCI0MDQuaHRtbFwiKSBmb3IgdGhlIHdlYnNpdGUuXG4gICAqIGB3ZWJzaXRlSW5kZXhEb2N1bWVudGAgbXVzdCBhbHNvIGJlIHNldCBpZiB0aGlzIGlzIHNldC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBlcnJvciBkb2N1bWVudC5cbiAgICovXG4gIHJlYWRvbmx5IHdlYnNpdGVFcnJvckRvY3VtZW50Pzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBTcGVjaWZpZXMgdGhlIHJlZGlyZWN0IGJlaGF2aW9yIG9mIGFsbCByZXF1ZXN0cyB0byBhIHdlYnNpdGUgZW5kcG9pbnQgb2YgYSBidWNrZXQuXG4gICAqXG4gICAqIElmIHlvdSBzcGVjaWZ5IHRoaXMgcHJvcGVydHksIHlvdSBjYW4ndCBzcGVjaWZ5IFwid2Vic2l0ZUluZGV4RG9jdW1lbnRcIiwgXCJ3ZWJzaXRlRXJyb3JEb2N1bWVudFwiIG5vciAsIFwid2Vic2l0ZVJvdXRpbmdSdWxlc1wiLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE5vIHJlZGlyZWN0aW9uLlxuICAgKi9cbiAgcmVhZG9ubHkgd2Vic2l0ZVJlZGlyZWN0PzogUmVkaXJlY3RUYXJnZXQ7XG5cbiAgLyoqXG4gICAqIFJ1bGVzIHRoYXQgZGVmaW5lIHdoZW4gYSByZWRpcmVjdCBpcyBhcHBsaWVkIGFuZCB0aGUgcmVkaXJlY3QgYmVoYXZpb3JcbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyByZWRpcmVjdGlvbiBydWxlcy5cbiAgICovXG4gIHJlYWRvbmx5IHdlYnNpdGVSb3V0aW5nUnVsZXM/OiBSb3V0aW5nUnVsZVtdO1xuXG4gIC8qKlxuICAgKiBTcGVjaWZpZXMgYSBjYW5uZWQgQUNMIHRoYXQgZ3JhbnRzIHByZWRlZmluZWQgcGVybWlzc2lvbnMgdG8gdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogQGRlZmF1bHQgQnVja2V0QWNjZXNzQ29udHJvbC5QUklWQVRFXG4gICAqL1xuICByZWFkb25seSBhY2Nlc3NDb250cm9sPzogQnVja2V0QWNjZXNzQ29udHJvbDtcblxuICAvKipcbiAgICogR3JhbnRzIHB1YmxpYyByZWFkIGFjY2VzcyB0byBhbGwgb2JqZWN0cyBpbiB0aGUgYnVja2V0LlxuICAgKiBTaW1pbGFyIHRvIGNhbGxpbmcgYGJ1Y2tldC5ncmFudFB1YmxpY0FjY2VzcygpYFxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgcHVibGljUmVhZEFjY2Vzcz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBibG9jayBwdWJsaWMgYWNjZXNzIGNvbmZpZ3VyYXRpb24gb2YgdGhpcyBidWNrZXQuXG4gICAqXG4gICAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvYWNjZXNzLWNvbnRyb2wtYmxvY2stcHVibGljLWFjY2Vzcy5odG1sXG4gICAqXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gQ2xvdWRGb3JtYXRpb24gZGVmYXVsdHMgd2lsbCBhcHBseS4gTmV3IGJ1Y2tldHMgYW5kIG9iamVjdHMgZG9uJ3QgYWxsb3cgcHVibGljIGFjY2VzcywgYnV0IHVzZXJzIGNhbiBtb2RpZnkgYnVja2V0IHBvbGljaWVzIG9yIG9iamVjdCBwZXJtaXNzaW9ucyB0byBhbGxvdyBwdWJsaWMgYWNjZXNzXG4gICAqL1xuICByZWFkb25seSBibG9ja1B1YmxpY0FjY2Vzcz86IEJsb2NrUHVibGljQWNjZXNzO1xuXG4gIC8qKlxuICAgKiBUaGUgbWV0cmljcyBjb25maWd1cmF0aW9uIG9mIHRoaXMgYnVja2V0LlxuICAgKlxuICAgKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BV1NDbG91ZEZvcm1hdGlvbi9sYXRlc3QvVXNlckd1aWRlL2F3cy1wcm9wZXJ0aWVzLXMzLWJ1Y2tldC1tZXRyaWNzY29uZmlndXJhdGlvbi5odG1sXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gbWV0cmljcyBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgcmVhZG9ubHkgbWV0cmljcz86IEJ1Y2tldE1ldHJpY3NbXTtcblxuICAvKipcbiAgICogVGhlIENPUlMgY29uZmlndXJhdGlvbiBvZiB0aGlzIGJ1Y2tldC5cbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQVdTQ2xvdWRGb3JtYXRpb24vbGF0ZXN0L1VzZXJHdWlkZS9hd3MtcHJvcGVydGllcy1zMy1idWNrZXQtY29ycy5odG1sXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gQ09SUyBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgcmVhZG9ubHkgY29ycz86IENvcnNSdWxlW107XG5cbiAgLyoqXG4gICAqIERlc3RpbmF0aW9uIGJ1Y2tldCBmb3IgdGhlIHNlcnZlciBhY2Nlc3MgbG9ncy5cbiAgICogQGRlZmF1bHQgLSBJZiBcInNlcnZlckFjY2Vzc0xvZ3NQcmVmaXhcIiB1bmRlZmluZWQgLSBhY2Nlc3MgbG9ncyBkaXNhYmxlZCwgb3RoZXJ3aXNlIC0gbG9nIHRvIGN1cnJlbnQgYnVja2V0LlxuICAgKi9cbiAgcmVhZG9ubHkgc2VydmVyQWNjZXNzTG9nc0J1Y2tldD86IElCdWNrZXQ7XG5cbiAgLyoqXG4gICAqIE9wdGlvbmFsIGxvZyBmaWxlIHByZWZpeCB0byB1c2UgZm9yIHRoZSBidWNrZXQncyBhY2Nlc3MgbG9ncy5cbiAgICogSWYgZGVmaW5lZCB3aXRob3V0IFwic2VydmVyQWNjZXNzTG9nc0J1Y2tldFwiLCBlbmFibGVzIGFjY2VzcyBsb2dzIHRvIGN1cnJlbnQgYnVja2V0IHdpdGggdGhpcyBwcmVmaXguXG4gICAqIEBkZWZhdWx0IC0gTm8gbG9nIGZpbGUgcHJlZml4XG4gICAqL1xuICByZWFkb25seSBzZXJ2ZXJBY2Nlc3NMb2dzUHJlZml4Pzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgaW52ZW50b3J5IGNvbmZpZ3VyYXRpb24gb2YgdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9zdG9yYWdlLWludmVudG9yeS5odG1sXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gaW52ZW50b3J5IGNvbmZpZ3VyYXRpb25cbiAgICovXG4gIHJlYWRvbmx5IGludmVudG9yaWVzPzogSW52ZW50b3J5W107XG4gIC8qKlxuICAgKiBUaGUgb2JqZWN0T3duZXJzaGlwIG9mIHRoZSBidWNrZXQuXG4gICAqXG4gICAqIEBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvYWJvdXQtb2JqZWN0LW93bmVyc2hpcC5odG1sXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gT2JqZWN0T3duZXJzaGlwIGNvbmZpZ3VyYXRpb24sIHVwbG9hZGluZyBhY2NvdW50IHdpbGwgb3duIHRoZSBvYmplY3QuXG4gICAqXG4gICAqL1xuICByZWFkb25seSBvYmplY3RPd25lcnNoaXA/OiBPYmplY3RPd25lcnNoaXA7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdGhpcyBidWNrZXQgc2hvdWxkIGhhdmUgdHJhbnNmZXIgYWNjZWxlcmF0aW9uIHR1cm5lZCBvbiBvciBub3QuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSB0cmFuc2ZlckFjY2VsZXJhdGlvbj86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSByb2xlIHRvIGJlIHVzZWQgYnkgdGhlIG5vdGlmaWNhdGlvbnMgaGFuZGxlclxuICAgKlxuICAgKiBAZGVmYXVsdCAtIGEgbmV3IHJvbGUgd2lsbCBiZSBjcmVhdGVkLlxuICAgKi9cbiAgcmVhZG9ubHkgbm90aWZpY2F0aW9uc0hhbmRsZXJSb2xlPzogaWFtLklSb2xlO1xuXG4gIC8qKlxuICAgKiBJbnRlbGlnZW50IFRpZXJpbmcgQ29uZmlndXJhdGlvbnNcbiAgICpcbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L3VzZXJndWlkZS9pbnRlbGxpZ2VudC10aWVyaW5nLmh0bWxcbiAgICpcbiAgICogQGRlZmF1bHQgTm8gSW50ZWxsaWdlbnQgVGlpZXJpbmcgQ29uZmlndXJhdGlvbnMuXG4gICAqL1xuICByZWFkb25seSBpbnRlbGxpZ2VudFRpZXJpbmdDb25maWd1cmF0aW9ucz86IEludGVsbGlnZW50VGllcmluZ0NvbmZpZ3VyYXRpb25bXTtcbn1cblxuXG4vKipcbiAqIFRhZ1xuICovXG5leHBvcnQgaW50ZXJmYWNlIFRhZyB7XG5cbiAgLyoqXG4gICAqIGtleSB0byBlIHRhZ2dlZFxuICAgKi9cbiAgcmVhZG9ubHkga2V5OiBzdHJpbmc7XG4gIC8qKlxuICAgKiBhZGRpdGlvbmFsIHZhbHVlXG4gICAqL1xuICByZWFkb25seSB2YWx1ZTogc3RyaW5nO1xufVxuXG4vKipcbiAqIEFuIFMzIGJ1Y2tldCB3aXRoIGFzc29jaWF0ZWQgcG9saWN5IG9iamVjdHNcbiAqXG4gKiBUaGlzIGJ1Y2tldCBkb2VzIG5vdCB5ZXQgaGF2ZSBhbGwgZmVhdHVyZXMgdGhhdCBleHBvc2VkIGJ5IHRoZSB1bmRlcmx5aW5nXG4gKiBCdWNrZXRSZXNvdXJjZS5cbiAqXG4gKiBAZXhhbXBsZVxuICpcbiAqIG5ldyBCdWNrZXQoc2NvcGUsICdCdWNrZXQnLCB7XG4gKiAgIGJsb2NrUHVibGljQWNjZXNzOiBCbG9ja1B1YmxpY0FjY2Vzcy5CTE9DS19BTEwsXG4gKiAgIGVuY3J5cHRpb246IEJ1Y2tldEVuY3J5cHRpb24uUzNfTUFOQUdFRCxcbiAqICAgZW5mb3JjZVNTTDogdHJ1ZSxcbiAqICAgdmVyc2lvbmVkOiB0cnVlLFxuICogICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LlJFVEFJTixcbiAqIH0pO1xuICpcbiAqL1xuZXhwb3J0IGNsYXNzIEJ1Y2tldCBleHRlbmRzIEJ1Y2tldEJhc2Uge1xuXG4gIHB1YmxpYyBzdGF0aWMgZnJvbUJ1Y2tldEFybihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBidWNrZXRBcm46IHN0cmluZyk6IElCdWNrZXQge1xuICAgIHJldHVybiBCdWNrZXQuZnJvbUJ1Y2tldEF0dHJpYnV0ZXMoc2NvcGUsIGlkLCB7IGJ1Y2tldEFybiB9KTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgZnJvbUJ1Y2tldE5hbWUoc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgYnVja2V0TmFtZTogc3RyaW5nKTogSUJ1Y2tldCB7XG4gICAgcmV0dXJuIEJ1Y2tldC5mcm9tQnVja2V0QXR0cmlidXRlcyhzY29wZSwgaWQsIHsgYnVja2V0TmFtZSB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgQnVja2V0IGNvbnN0cnVjdCB0aGF0IHJlcHJlc2VudHMgYW4gZXh0ZXJuYWwgYnVja2V0LlxuICAgKlxuICAgKiBAcGFyYW0gc2NvcGUgVGhlIHBhcmVudCBjcmVhdGluZyBjb25zdHJ1Y3QgKHVzdWFsbHkgYHRoaXNgKS5cbiAgICogQHBhcmFtIGlkIFRoZSBjb25zdHJ1Y3QncyBuYW1lLlxuICAgKiBAcGFyYW0gYXR0cnMgQSBgQnVja2V0QXR0cmlidXRlc2Agb2JqZWN0LiBDYW4gYmUgb2J0YWluZWQgZnJvbSBhIGNhbGwgdG9cbiAgICogYGJ1Y2tldC5leHBvcnQoKWAgb3IgbWFudWFsbHkgY3JlYXRlZC5cbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgZnJvbUJ1Y2tldEF0dHJpYnV0ZXMoc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgYXR0cnM6IEJ1Y2tldEF0dHJpYnV0ZXMpOiBJQnVja2V0IHtcbiAgICBjb25zdCBzdGFjayA9IFN0YWNrLm9mKHNjb3BlKTtcbiAgICBjb25zdCByZWdpb24gPSBhdHRycy5yZWdpb24gPz8gc3RhY2sucmVnaW9uO1xuICAgIGNvbnN0IHVybFN1ZmZpeCA9IHN0YWNrLnVybFN1ZmZpeDtcblxuICAgIGNvbnN0IGJ1Y2tldE5hbWUgPSBwYXJzZUJ1Y2tldE5hbWUoc2NvcGUsIGF0dHJzKTtcbiAgICBpZiAoIWJ1Y2tldE5hbWUpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQnVja2V0IG5hbWUgaXMgcmVxdWlyZWQnKTtcbiAgICB9XG4gICAgQnVja2V0LnZhbGlkYXRlQnVja2V0TmFtZShidWNrZXROYW1lKTtcblxuICAgIGNvbnN0IG5ld1VybEZvcm1hdCA9IGF0dHJzLmJ1Y2tldFdlYnNpdGVOZXdVcmxGb3JtYXQgPT09IHVuZGVmaW5lZFxuICAgICAgPyBmYWxzZVxuICAgICAgOiBhdHRycy5idWNrZXRXZWJzaXRlTmV3VXJsRm9ybWF0O1xuXG4gICAgY29uc3Qgd2Vic2l0ZURvbWFpbiA9IG5ld1VybEZvcm1hdFxuICAgICAgPyBgJHtidWNrZXROYW1lfS5zMy13ZWJzaXRlLiR7cmVnaW9ufS4ke3VybFN1ZmZpeH1gXG4gICAgICA6IGAke2J1Y2tldE5hbWV9LnMzLXdlYnNpdGUtJHtyZWdpb259LiR7dXJsU3VmZml4fWA7XG5cbiAgICBjbGFzcyBJbXBvcnQgZXh0ZW5kcyBCdWNrZXRCYXNlIHtcbiAgICAgIHB1YmxpYyByZWFkb25seSBidWNrZXROYW1lID0gYnVja2V0TmFtZSE7XG4gICAgICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0QXJuID0gcGFyc2VCdWNrZXRBcm4oc2NvcGUsIGF0dHJzKTtcbiAgICAgIHB1YmxpYyByZWFkb25seSBidWNrZXREb21haW5OYW1lID0gYXR0cnMuYnVja2V0RG9tYWluTmFtZSB8fCBgJHtidWNrZXROYW1lfS5zMy4ke3VybFN1ZmZpeH1gO1xuICAgICAgcHVibGljIHJlYWRvbmx5IGJ1Y2tldFdlYnNpdGVVcmwgPSBhdHRycy5idWNrZXRXZWJzaXRlVXJsIHx8IGBodHRwOi8vJHt3ZWJzaXRlRG9tYWlufWA7XG4gICAgICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0V2Vic2l0ZURvbWFpbk5hbWUgPSBhdHRycy5idWNrZXRXZWJzaXRlVXJsID8gRm4uc2VsZWN0KDIsIEZuLnNwbGl0KCcvJywgYXR0cnMuYnVja2V0V2Vic2l0ZVVybCkpIDogd2Vic2l0ZURvbWFpbjtcbiAgICAgIHB1YmxpYyByZWFkb25seSBidWNrZXRSZWdpb25hbERvbWFpbk5hbWUgPSBhdHRycy5idWNrZXRSZWdpb25hbERvbWFpbk5hbWUgfHwgYCR7YnVja2V0TmFtZX0uczMuJHtyZWdpb259LiR7dXJsU3VmZml4fWA7XG4gICAgICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0RHVhbFN0YWNrRG9tYWluTmFtZSA9IGF0dHJzLmJ1Y2tldER1YWxTdGFja0RvbWFpbk5hbWUgfHwgYCR7YnVja2V0TmFtZX0uczMuZHVhbHN0YWNrLiR7cmVnaW9ufS4ke3VybFN1ZmZpeH1gO1xuICAgICAgcHVibGljIHJlYWRvbmx5IGJ1Y2tldFdlYnNpdGVOZXdVcmxGb3JtYXQgPSBuZXdVcmxGb3JtYXQ7XG4gICAgICBwdWJsaWMgcmVhZG9ubHkgZW5jcnlwdGlvbktleSA9IGF0dHJzLmVuY3J5cHRpb25LZXk7XG4gICAgICBwdWJsaWMgcmVhZG9ubHkgaXNXZWJzaXRlID0gYXR0cnMuaXNXZWJzaXRlID8/IGZhbHNlO1xuICAgICAgcHVibGljIHBvbGljeT86IEJ1Y2tldFBvbGljeSA9IHVuZGVmaW5lZDtcbiAgICAgIHByb3RlY3RlZCBhdXRvQ3JlYXRlUG9saWN5ID0gZmFsc2U7XG4gICAgICBwcm90ZWN0ZWQgZGlzYWxsb3dQdWJsaWNBY2Nlc3MgPSBmYWxzZTtcbiAgICAgIHByb3RlY3RlZCBub3RpZmljYXRpb25zSGFuZGxlclJvbGUgPSBhdHRycy5ub3RpZmljYXRpb25zSGFuZGxlclJvbGU7XG5cbiAgICAgIC8qKlxuICAgICAgICogRXhwb3J0cyB0aGlzIGJ1Y2tldCBmcm9tIHRoZSBzdGFjay5cbiAgICAgICAqL1xuICAgICAgcHVibGljIGV4cG9ydCgpIHtcbiAgICAgICAgcmV0dXJuIGF0dHJzO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCwge1xuICAgICAgYWNjb3VudDogYXR0cnMuYWNjb3VudCxcbiAgICAgIHJlZ2lvbjogYXR0cnMucmVnaW9uLFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFRocm93biBhbiBleGNlcHRpb24gaWYgdGhlIGdpdmVuIGJ1Y2tldCBuYW1lIGlzIG5vdCB2YWxpZC5cbiAgICpcbiAgICogQHBhcmFtIHBoeXNpY2FsTmFtZSBuYW1lIG9mIHRoZSBidWNrZXQuXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVja2V0TmFtZShwaHlzaWNhbE5hbWU6IHN0cmluZyk6IHZvaWQge1xuICAgIGNvbnN0IGJ1Y2tldE5hbWUgPSBwaHlzaWNhbE5hbWU7XG4gICAgaWYgKCFidWNrZXROYW1lIHx8IFRva2VuLmlzVW5yZXNvbHZlZChidWNrZXROYW1lKSkge1xuICAgICAgLy8gdGhlIG5hbWUgaXMgYSBsYXRlLWJvdW5kIHZhbHVlLCBub3QgYSBkZWZpbmVkIHN0cmluZyxcbiAgICAgIC8vIHNvIHNraXAgdmFsaWRhdGlvblxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGVycm9yczogc3RyaW5nW10gPSBbXTtcblxuICAgIC8vIFJ1bGVzIGNvZGlmaWVkIGZyb20gaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblMzL2xhdGVzdC9kZXYvQnVja2V0UmVzdHJpY3Rpb25zLmh0bWxcbiAgICBpZiAoYnVja2V0TmFtZS5sZW5ndGggPCAzIHx8IGJ1Y2tldE5hbWUubGVuZ3RoID4gNjMpIHtcbiAgICAgIGVycm9ycy5wdXNoKCdCdWNrZXQgbmFtZSBtdXN0IGJlIGF0IGxlYXN0IDMgYW5kIG5vIG1vcmUgdGhhbiA2MyBjaGFyYWN0ZXJzJyk7XG4gICAgfVxuICAgIGNvbnN0IGNoYXJzZXRNYXRjaCA9IGJ1Y2tldE5hbWUubWF0Y2goL1teYS16MC05Li1dLyk7XG4gICAgaWYgKGNoYXJzZXRNYXRjaCkge1xuICAgICAgZXJyb3JzLnB1c2goJ0J1Y2tldCBuYW1lIG11c3Qgb25seSBjb250YWluIGxvd2VyY2FzZSBjaGFyYWN0ZXJzIGFuZCB0aGUgc3ltYm9scywgcGVyaW9kICguKSBhbmQgZGFzaCAoLSkgJ1xuICAgICAgICArIGAob2Zmc2V0OiAke2NoYXJzZXRNYXRjaC5pbmRleH0pYCk7XG4gICAgfVxuICAgIGlmICghL1thLXowLTldLy50ZXN0KGJ1Y2tldE5hbWUuY2hhckF0KDApKSkge1xuICAgICAgZXJyb3JzLnB1c2goJ0J1Y2tldCBuYW1lIG11c3Qgc3RhcnQgYW5kIGVuZCB3aXRoIGEgbG93ZXJjYXNlIGNoYXJhY3RlciBvciBudW1iZXIgJ1xuICAgICAgICArICcob2Zmc2V0OiAwKScpO1xuICAgIH1cbiAgICBpZiAoIS9bYS16MC05XS8udGVzdChidWNrZXROYW1lLmNoYXJBdChidWNrZXROYW1lLmxlbmd0aCAtIDEpKSkge1xuICAgICAgZXJyb3JzLnB1c2goJ0J1Y2tldCBuYW1lIG11c3Qgc3RhcnQgYW5kIGVuZCB3aXRoIGEgbG93ZXJjYXNlIGNoYXJhY3RlciBvciBudW1iZXIgJ1xuICAgICAgICArIGAob2Zmc2V0OiAke2J1Y2tldE5hbWUubGVuZ3RoIC0gMX0pYCk7XG4gICAgfVxuICAgIGNvbnN0IGNvbnNlY1N5bWJvbE1hdGNoID0gYnVja2V0TmFtZS5tYXRjaCgvXFwuLXwtXFwufFxcLlxcLi8pO1xuICAgIGlmIChjb25zZWNTeW1ib2xNYXRjaCkge1xuICAgICAgZXJyb3JzLnB1c2goJ0J1Y2tldCBuYW1lIG11c3Qgbm90IGhhdmUgZGFzaCBuZXh0IHRvIHBlcmlvZCwgb3IgcGVyaW9kIG5leHQgdG8gZGFzaCwgb3IgY29uc2VjdXRpdmUgcGVyaW9kcyAnXG4gICAgICAgICsgYChvZmZzZXQ6ICR7Y29uc2VjU3ltYm9sTWF0Y2guaW5kZXh9KWApO1xuICAgIH1cbiAgICBpZiAoL15cXGR7MSwzfVxcLlxcZHsxLDN9XFwuXFxkezEsM31cXC5cXGR7MSwzfSQvLnRlc3QoYnVja2V0TmFtZSkpIHtcbiAgICAgIGVycm9ycy5wdXNoKCdCdWNrZXQgbmFtZSBtdXN0IG5vdCByZXNlbWJsZSBhbiBJUCBhZGRyZXNzJyk7XG4gICAgfVxuXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEludmFsaWQgUzMgYnVja2V0IG5hbWUgKHZhbHVlOiAke2J1Y2tldE5hbWV9KSR7RU9MfSR7ZXJyb3JzLmpvaW4oRU9MKX1gKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0QXJuOiBzdHJpbmc7XG4gIHB1YmxpYyByZWFkb25seSBidWNrZXROYW1lOiBzdHJpbmc7XG4gIHB1YmxpYyByZWFkb25seSBidWNrZXREb21haW5OYW1lOiBzdHJpbmc7XG4gIHB1YmxpYyByZWFkb25seSBidWNrZXRXZWJzaXRlVXJsOiBzdHJpbmc7XG4gIHB1YmxpYyByZWFkb25seSBidWNrZXRXZWJzaXRlRG9tYWluTmFtZTogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0RHVhbFN0YWNrRG9tYWluTmFtZTogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgYnVja2V0UmVnaW9uYWxEb21haW5OYW1lOiBzdHJpbmc7XG5cbiAgcHVibGljIHJlYWRvbmx5IGVuY3J5cHRpb25LZXk/OiBrbXMuSUtleTtcbiAgcHVibGljIHJlYWRvbmx5IGlzV2Vic2l0ZT86IGJvb2xlYW47XG4gIHB1YmxpYyBwb2xpY3k/OiBCdWNrZXRQb2xpY3k7XG4gIHByb3RlY3RlZCBhdXRvQ3JlYXRlUG9saWN5ID0gdHJ1ZTtcbiAgcHJvdGVjdGVkIGRpc2FsbG93UHVibGljQWNjZXNzPzogYm9vbGVhbjtcbiAgcHJpdmF0ZSBhY2Nlc3NDb250cm9sPzogQnVja2V0QWNjZXNzQ29udHJvbDtcbiAgcHJpdmF0ZSByZWFkb25seSBsaWZlY3ljbGVSdWxlczogTGlmZWN5Y2xlUnVsZVtdID0gW107XG4gIHByaXZhdGUgcmVhZG9ubHkgdmVyc2lvbmVkPzogYm9vbGVhbjtcbiAgcHJpdmF0ZSByZWFkb25seSBldmVudEJyaWRnZUVuYWJsZWQ/OiBib29sZWFuO1xuICBwcml2YXRlIHJlYWRvbmx5IG1ldHJpY3M6IEJ1Y2tldE1ldHJpY3NbXSA9IFtdO1xuICBwcml2YXRlIHJlYWRvbmx5IGNvcnM6IENvcnNSdWxlW10gPSBbXTtcbiAgcHJpdmF0ZSByZWFkb25seSBpbnZlbnRvcmllczogSW52ZW50b3J5W10gPSBbXTtcbiAgcHJpdmF0ZSByZWFkb25seSBfcmVzb3VyY2U6IENmbkJ1Y2tldDtcblxuICBjb25zdHJ1Y3RvcihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBwcm9wczogQnVja2V0UHJvcHMgPSB7fSkge1xuICAgIHN1cGVyKHNjb3BlLCBpZCwge1xuICAgICAgcGh5c2ljYWxOYW1lOiBwcm9wcy5idWNrZXROYW1lLFxuICAgIH0pO1xuXG4gICAgdGhpcy5ub3RpZmljYXRpb25zSGFuZGxlclJvbGUgPSBwcm9wcy5ub3RpZmljYXRpb25zSGFuZGxlclJvbGU7XG5cbiAgICBjb25zdCB7IGJ1Y2tldEVuY3J5cHRpb24sIGVuY3J5cHRpb25LZXkgfSA9IHRoaXMucGFyc2VFbmNyeXB0aW9uKHByb3BzKTtcblxuICAgIEJ1Y2tldC52YWxpZGF0ZUJ1Y2tldE5hbWUodGhpcy5waHlzaWNhbE5hbWUpO1xuXG4gICAgY29uc3Qgd2Vic2l0ZUNvbmZpZ3VyYXRpb24gPSB0aGlzLnJlbmRlcldlYnNpdGVDb25maWd1cmF0aW9uKHByb3BzKTtcbiAgICB0aGlzLmlzV2Vic2l0ZSA9ICh3ZWJzaXRlQ29uZmlndXJhdGlvbiAhPT0gdW5kZWZpbmVkKTtcblxuICAgIGNvbnN0IHJlc291cmNlID0gbmV3IENmbkJ1Y2tldCh0aGlzLCAnUmVzb3VyY2UnLCB7XG4gICAgICBidWNrZXROYW1lOiB0aGlzLnBoeXNpY2FsTmFtZSxcbiAgICAgIGJ1Y2tldEVuY3J5cHRpb24sXG4gICAgICB2ZXJzaW9uaW5nQ29uZmlndXJhdGlvbjogcHJvcHMudmVyc2lvbmVkID8geyBzdGF0dXM6ICdFbmFibGVkJyB9IDogdW5kZWZpbmVkLFxuICAgICAgbGlmZWN5Y2xlQ29uZmlndXJhdGlvbjogTGF6eS5hbnkoeyBwcm9kdWNlOiAoKSA9PiB0aGlzLnBhcnNlTGlmZWN5Y2xlQ29uZmlndXJhdGlvbigpIH0pLFxuICAgICAgd2Vic2l0ZUNvbmZpZ3VyYXRpb24sXG4gICAgICBwdWJsaWNBY2Nlc3NCbG9ja0NvbmZpZ3VyYXRpb246IHByb3BzLmJsb2NrUHVibGljQWNjZXNzLFxuICAgICAgbWV0cmljc0NvbmZpZ3VyYXRpb25zOiBMYXp5LmFueSh7IHByb2R1Y2U6ICgpID0+IHRoaXMucGFyc2VNZXRyaWNDb25maWd1cmF0aW9uKCkgfSksXG4gICAgICBjb3JzQ29uZmlndXJhdGlvbjogTGF6eS5hbnkoeyBwcm9kdWNlOiAoKSA9PiB0aGlzLnBhcnNlQ29yc0NvbmZpZ3VyYXRpb24oKSB9KSxcbiAgICAgIGFjY2Vzc0NvbnRyb2w6IExhenkuc3RyaW5nKHsgcHJvZHVjZTogKCkgPT4gdGhpcy5hY2Nlc3NDb250cm9sIH0pLFxuICAgICAgbG9nZ2luZ0NvbmZpZ3VyYXRpb246IHRoaXMucGFyc2VTZXJ2ZXJBY2Nlc3NMb2dzKHByb3BzKSxcbiAgICAgIGludmVudG9yeUNvbmZpZ3VyYXRpb25zOiBMYXp5LmFueSh7IHByb2R1Y2U6ICgpID0+IHRoaXMucGFyc2VJbnZlbnRvcnlDb25maWd1cmF0aW9uKCkgfSksXG4gICAgICBvd25lcnNoaXBDb250cm9sczogdGhpcy5wYXJzZU93bmVyc2hpcENvbnRyb2xzKHByb3BzKSxcbiAgICAgIGFjY2VsZXJhdGVDb25maWd1cmF0aW9uOiBwcm9wcy50cmFuc2ZlckFjY2VsZXJhdGlvbiA/IHsgYWNjZWxlcmF0aW9uU3RhdHVzOiAnRW5hYmxlZCcgfSA6IHVuZGVmaW5lZCxcbiAgICAgIGludGVsbGlnZW50VGllcmluZ0NvbmZpZ3VyYXRpb25zOiB0aGlzLnBhcnNlVGllcmluZ0NvbmZpZyhwcm9wcyksXG4gICAgfSk7XG4gICAgdGhpcy5fcmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgIHJlc291cmNlLmFwcGx5UmVtb3ZhbFBvbGljeShwcm9wcy5yZW1vdmFsUG9saWN5KTtcblxuICAgIHRoaXMudmVyc2lvbmVkID0gcHJvcHMudmVyc2lvbmVkO1xuICAgIHRoaXMuZW5jcnlwdGlvbktleSA9IGVuY3J5cHRpb25LZXk7XG4gICAgdGhpcy5ldmVudEJyaWRnZUVuYWJsZWQgPSBwcm9wcy5ldmVudEJyaWRnZUVuYWJsZWQ7XG5cbiAgICB0aGlzLmJ1Y2tldE5hbWUgPSB0aGlzLmdldFJlc291cmNlTmFtZUF0dHJpYnV0ZShyZXNvdXJjZS5yZWYpO1xuICAgIHRoaXMuYnVja2V0QXJuID0gdGhpcy5nZXRSZXNvdXJjZUFybkF0dHJpYnV0ZShyZXNvdXJjZS5hdHRyQXJuLCB7XG4gICAgICByZWdpb246ICcnLFxuICAgICAgYWNjb3VudDogJycsXG4gICAgICBzZXJ2aWNlOiAnczMnLFxuICAgICAgcmVzb3VyY2U6IHRoaXMucGh5c2ljYWxOYW1lLFxuICAgIH0pO1xuXG4gICAgdGhpcy5idWNrZXREb21haW5OYW1lID0gcmVzb3VyY2UuYXR0ckRvbWFpbk5hbWU7XG4gICAgdGhpcy5idWNrZXRXZWJzaXRlVXJsID0gcmVzb3VyY2UuYXR0cldlYnNpdGVVcmw7XG4gICAgdGhpcy5idWNrZXRXZWJzaXRlRG9tYWluTmFtZSA9IEZuLnNlbGVjdCgyLCBGbi5zcGxpdCgnLycsIHRoaXMuYnVja2V0V2Vic2l0ZVVybCkpO1xuICAgIHRoaXMuYnVja2V0RHVhbFN0YWNrRG9tYWluTmFtZSA9IHJlc291cmNlLmF0dHJEdWFsU3RhY2tEb21haW5OYW1lO1xuICAgIHRoaXMuYnVja2V0UmVnaW9uYWxEb21haW5OYW1lID0gcmVzb3VyY2UuYXR0clJlZ2lvbmFsRG9tYWluTmFtZTtcblxuICAgIHRoaXMuZGlzYWxsb3dQdWJsaWNBY2Nlc3MgPSBwcm9wcy5ibG9ja1B1YmxpY0FjY2VzcyAmJiBwcm9wcy5ibG9ja1B1YmxpY0FjY2Vzcy5ibG9ja1B1YmxpY1BvbGljeTtcbiAgICB0aGlzLmFjY2Vzc0NvbnRyb2wgPSBwcm9wcy5hY2Nlc3NDb250cm9sO1xuXG4gICAgLy8gRW5mb3JjZSBBV1MgRm91bmRhdGlvbmFsIFNlY3VyaXR5IEJlc3QgUHJhY3RpY2VcbiAgICBpZiAocHJvcHMuZW5mb3JjZVNTTCkge1xuICAgICAgdGhpcy5lbmZvcmNlU1NMU3RhdGVtZW50KCk7XG4gICAgfVxuXG4gICAgaWYgKHByb3BzLnNlcnZlckFjY2Vzc0xvZ3NCdWNrZXQgaW5zdGFuY2VvZiBCdWNrZXQpIHtcbiAgICAgIHByb3BzLnNlcnZlckFjY2Vzc0xvZ3NCdWNrZXQuYWxsb3dMb2dEZWxpdmVyeSgpO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgaW52ZW50b3J5IG9mIHByb3BzLmludmVudG9yaWVzID8/IFtdKSB7XG4gICAgICB0aGlzLmFkZEludmVudG9yeShpbnZlbnRvcnkpO1xuICAgIH1cblxuICAgIC8vIEFkZCBhbGwgYnVja2V0IG1ldHJpYyBjb25maWd1cmF0aW9ucyBydWxlc1xuICAgIChwcm9wcy5tZXRyaWNzIHx8IFtdKS5mb3JFYWNoKHRoaXMuYWRkTWV0cmljLmJpbmQodGhpcykpO1xuICAgIC8vIEFkZCBhbGwgY29ycyBjb25maWd1cmF0aW9uIHJ1bGVzXG4gICAgKHByb3BzLmNvcnMgfHwgW10pLmZvckVhY2godGhpcy5hZGRDb3JzUnVsZS5iaW5kKHRoaXMpKTtcblxuICAgIC8vIEFkZCBhbGwgbGlmZWN5Y2xlIHJ1bGVzXG4gICAgKHByb3BzLmxpZmVjeWNsZVJ1bGVzIHx8IFtdKS5mb3JFYWNoKHRoaXMuYWRkTGlmZWN5Y2xlUnVsZS5iaW5kKHRoaXMpKTtcblxuICAgIGlmIChwcm9wcy5wdWJsaWNSZWFkQWNjZXNzKSB7XG4gICAgICB0aGlzLmdyYW50UHVibGljQWNjZXNzKCk7XG4gICAgfVxuXG4gICAgaWYgKHByb3BzLmF1dG9EZWxldGVPYmplY3RzKSB7XG4gICAgICBpZiAocHJvcHMucmVtb3ZhbFBvbGljeSAhPT0gUmVtb3ZhbFBvbGljeS5ERVNUUk9ZKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQ2Fubm90IHVzZSBcXCdhdXRvRGVsZXRlT2JqZWN0c1xcJyBwcm9wZXJ0eSBvbiBhIGJ1Y2tldCB3aXRob3V0IHNldHRpbmcgcmVtb3ZhbCBwb2xpY3kgdG8gXFwnREVTVFJPWVxcJy4nKTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5lbmFibGVBdXRvRGVsZXRlT2JqZWN0cygpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmV2ZW50QnJpZGdlRW5hYmxlZCkge1xuICAgICAgdGhpcy5lbmFibGVFdmVudEJyaWRnZU5vdGlmaWNhdGlvbigpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBBZGQgYSBsaWZlY3ljbGUgcnVsZSB0byB0aGUgYnVja2V0XG4gICAqXG4gICAqIEBwYXJhbSBydWxlIFRoZSBydWxlIHRvIGFkZFxuICAgKi9cbiAgcHVibGljIGFkZExpZmVjeWNsZVJ1bGUocnVsZTogTGlmZWN5Y2xlUnVsZSkge1xuICAgIGlmICgocnVsZS5ub25jdXJyZW50VmVyc2lvbkV4cGlyYXRpb24gIT09IHVuZGVmaW5lZFxuICAgICAgfHwgKHJ1bGUubm9uY3VycmVudFZlcnNpb25UcmFuc2l0aW9ucyAmJiBydWxlLm5vbmN1cnJlbnRWZXJzaW9uVHJhbnNpdGlvbnMubGVuZ3RoID4gMCkpXG4gICAgICAmJiAhdGhpcy52ZXJzaW9uZWQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkNhbm5vdCB1c2UgJ25vbmN1cnJlbnQnIHJ1bGVzIG9uIGEgbm9udmVyc2lvbmVkIGJ1Y2tldFwiKTtcbiAgICB9XG5cbiAgICB0aGlzLmxpZmVjeWNsZVJ1bGVzLnB1c2gocnVsZSk7XG4gIH1cblxuICAvKipcbiAgICogQWRkcyBhIG1ldHJpY3MgY29uZmlndXJhdGlvbiBmb3IgdGhlIENsb3VkV2F0Y2ggcmVxdWVzdCBtZXRyaWNzIGZyb20gdGhlIGJ1Y2tldC5cbiAgICpcbiAgICogQHBhcmFtIG1ldHJpYyBUaGUgbWV0cmljIGNvbmZpZ3VyYXRpb24gdG8gYWRkXG4gICAqL1xuICBwdWJsaWMgYWRkTWV0cmljKG1ldHJpYzogQnVja2V0TWV0cmljcykge1xuICAgIHRoaXMubWV0cmljcy5wdXNoKG1ldHJpYyk7XG4gIH1cblxuICAvKipcbiAgICogQWRkcyBhIGNyb3NzLW9yaWdpbiBhY2Nlc3MgY29uZmlndXJhdGlvbiBmb3Igb2JqZWN0cyBpbiBhbiBBbWF6b24gUzMgYnVja2V0XG4gICAqXG4gICAqIEBwYXJhbSBydWxlIFRoZSBDT1JTIGNvbmZpZ3VyYXRpb24gcnVsZSB0byBhZGRcbiAgICovXG4gIHB1YmxpYyBhZGRDb3JzUnVsZShydWxlOiBDb3JzUnVsZSkge1xuICAgIHRoaXMuY29ycy5wdXNoKHJ1bGUpO1xuICB9XG5cbiAgLyoqXG4gICAqIEFkZCBhbiBpbnZlbnRvcnkgY29uZmlndXJhdGlvbi5cbiAgICpcbiAgICogQHBhcmFtIGludmVudG9yeSBjb25maWd1cmF0aW9uIHRvIGFkZFxuICAgKi9cbiAgcHVibGljIGFkZEludmVudG9yeShpbnZlbnRvcnk6IEludmVudG9yeSk6IHZvaWQge1xuICAgIHRoaXMuaW52ZW50b3JpZXMucHVzaChpbnZlbnRvcnkpO1xuICB9XG5cbiAgLyoqXG4gICAqIEFkZHMgYW4gaWFtIHN0YXRlbWVudCB0byBlbmZvcmNlIFNTTCByZXF1ZXN0cyBvbmx5LlxuICAgKi9cbiAgcHJpdmF0ZSBlbmZvcmNlU1NMU3RhdGVtZW50KCkge1xuICAgIGNvbnN0IHN0YXRlbWVudCA9IG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGFjdGlvbnM6IFsnczM6KiddLFxuICAgICAgY29uZGl0aW9uczoge1xuICAgICAgICBCb29sOiB7ICdhd3M6U2VjdXJlVHJhbnNwb3J0JzogJ2ZhbHNlJyB9LFxuICAgICAgfSxcbiAgICAgIGVmZmVjdDogaWFtLkVmZmVjdC5ERU5ZLFxuICAgICAgcmVzb3VyY2VzOiBbXG4gICAgICAgIHRoaXMuYnVja2V0QXJuLFxuICAgICAgICB0aGlzLmFybkZvck9iamVjdHMoJyonKSxcbiAgICAgIF0sXG4gICAgICBwcmluY2lwYWxzOiBbbmV3IGlhbS5BbnlQcmluY2lwYWwoKV0sXG4gICAgfSk7XG4gICAgdGhpcy5hZGRUb1Jlc291cmNlUG9saWN5KHN0YXRlbWVudCk7XG4gIH1cblxuICAvKipcbiAgICogU2V0IHVwIGtleSBwcm9wZXJ0aWVzIGFuZCByZXR1cm4gdGhlIEJ1Y2tldCBlbmNyeXB0aW9uIHByb3BlcnR5IGZyb20gdGhlXG4gICAqIHVzZXIncyBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgcHJpdmF0ZSBwYXJzZUVuY3J5cHRpb24ocHJvcHM6IEJ1Y2tldFByb3BzKToge1xuICAgIGJ1Y2tldEVuY3J5cHRpb24/OiBDZm5CdWNrZXQuQnVja2V0RW5jcnlwdGlvblByb3BlcnR5LFxuICAgIGVuY3J5cHRpb25LZXk/OiBrbXMuSUtleVxuICB9IHtcblxuICAgIC8vIGRlZmF1bHQgYmFzZWQgb24gd2hldGhlciBlbmNyeXB0aW9uS2V5IGlzIHNwZWNpZmllZFxuICAgIGxldCBlbmNyeXB0aW9uVHlwZSA9IHByb3BzLmVuY3J5cHRpb247XG4gICAgaWYgKGVuY3J5cHRpb25UeXBlID09PSB1bmRlZmluZWQpIHtcbiAgICAgIGVuY3J5cHRpb25UeXBlID0gcHJvcHMuZW5jcnlwdGlvbktleSA/IEJ1Y2tldEVuY3J5cHRpb24uS01TIDogQnVja2V0RW5jcnlwdGlvbi5VTkVOQ1JZUFRFRDtcbiAgICB9XG5cbiAgICAvLyBpZiBlbmNyeXB0aW9uIGtleSBpcyBzZXQsIGVuY3J5cHRpb24gbXVzdCBiZSBzZXQgdG8gS01TLlxuICAgIGlmIChlbmNyeXB0aW9uVHlwZSAhPT0gQnVja2V0RW5jcnlwdGlvbi5LTVMgJiYgcHJvcHMuZW5jcnlwdGlvbktleSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBlbmNyeXB0aW9uS2V5IGlzIHNwZWNpZmllZCwgc28gJ2VuY3J5cHRpb24nIG11c3QgYmUgc2V0IHRvIEtNUyAodmFsdWU6ICR7ZW5jcnlwdGlvblR5cGV9KWApO1xuICAgIH1cblxuICAgIC8vIGlmIGJ1Y2tldEtleUVuYWJsZWQgaXMgc2V0LCBlbmNyeXB0aW9uIG11c3QgYmUgc2V0IHRvIEtNUy5cbiAgICBpZiAocHJvcHMuYnVja2V0S2V5RW5hYmxlZCAmJiBlbmNyeXB0aW9uVHlwZSAhPT0gQnVja2V0RW5jcnlwdGlvbi5LTVMpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgYnVja2V0S2V5RW5hYmxlZCBpcyBzcGVjaWZpZWQsIHNvICdlbmNyeXB0aW9uJyBtdXN0IGJlIHNldCB0byBLTVMgKHZhbHVlOiAke2VuY3J5cHRpb25UeXBlfSlgKTtcbiAgICB9XG5cbiAgICBpZiAoZW5jcnlwdGlvblR5cGUgPT09IEJ1Y2tldEVuY3J5cHRpb24uVU5FTkNSWVBURUQpIHtcbiAgICAgIHJldHVybiB7IGJ1Y2tldEVuY3J5cHRpb246IHVuZGVmaW5lZCwgZW5jcnlwdGlvbktleTogdW5kZWZpbmVkIH07XG4gICAgfVxuXG4gICAgaWYgKGVuY3J5cHRpb25UeXBlID09PSBCdWNrZXRFbmNyeXB0aW9uLktNUykge1xuICAgICAgY29uc3QgZW5jcnlwdGlvbktleSA9IHByb3BzLmVuY3J5cHRpb25LZXkgfHwgbmV3IGttcy5LZXkodGhpcywgJ0tleScsIHtcbiAgICAgICAgZGVzY3JpcHRpb246IGBDcmVhdGVkIGJ5ICR7dGhpcy5ub2RlLnBhdGh9YCxcbiAgICAgIH0pO1xuXG4gICAgICBjb25zdCBidWNrZXRFbmNyeXB0aW9uID0ge1xuICAgICAgICBzZXJ2ZXJTaWRlRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb246IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBidWNrZXRLZXlFbmFibGVkOiBwcm9wcy5idWNrZXRLZXlFbmFibGVkLFxuICAgICAgICAgICAgc2VydmVyU2lkZUVuY3J5cHRpb25CeURlZmF1bHQ6IHtcbiAgICAgICAgICAgICAgc3NlQWxnb3JpdGhtOiAnYXdzOmttcycsXG4gICAgICAgICAgICAgIGttc01hc3RlcktleUlkOiBlbmNyeXB0aW9uS2V5LmtleUFybixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH07XG4gICAgICByZXR1cm4geyBlbmNyeXB0aW9uS2V5LCBidWNrZXRFbmNyeXB0aW9uIH07XG4gICAgfVxuXG4gICAgaWYgKGVuY3J5cHRpb25UeXBlID09PSBCdWNrZXRFbmNyeXB0aW9uLlMzX01BTkFHRUQpIHtcbiAgICAgIGNvbnN0IGJ1Y2tldEVuY3J5cHRpb24gPSB7XG4gICAgICAgIHNlcnZlclNpZGVFbmNyeXB0aW9uQ29uZmlndXJhdGlvbjogW1xuICAgICAgICAgIHsgc2VydmVyU2lkZUVuY3J5cHRpb25CeURlZmF1bHQ6IHsgc3NlQWxnb3JpdGhtOiAnQUVTMjU2JyB9IH0sXG4gICAgICAgIF0sXG4gICAgICB9O1xuXG4gICAgICByZXR1cm4geyBidWNrZXRFbmNyeXB0aW9uIH07XG4gICAgfVxuXG4gICAgaWYgKGVuY3J5cHRpb25UeXBlID09PSBCdWNrZXRFbmNyeXB0aW9uLktNU19NQU5BR0VEKSB7XG4gICAgICBjb25zdCBidWNrZXRFbmNyeXB0aW9uID0ge1xuICAgICAgICBzZXJ2ZXJTaWRlRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb246IFtcbiAgICAgICAgICB7IHNlcnZlclNpZGVFbmNyeXB0aW9uQnlEZWZhdWx0OiB7IHNzZUFsZ29yaXRobTogJ2F3czprbXMnIH0gfSxcbiAgICAgICAgXSxcbiAgICAgIH07XG4gICAgICByZXR1cm4geyBidWNrZXRFbmNyeXB0aW9uIH07XG4gICAgfVxuXG4gICAgdGhyb3cgbmV3IEVycm9yKGBVbmV4cGVjdGVkICdlbmNyeXB0aW9uVHlwZSc6ICR7ZW5jcnlwdGlvblR5cGV9YCk7XG4gIH1cblxuICAvKipcbiAgICogUGFyc2UgdGhlIGxpZmVjeWNsZSBjb25maWd1cmF0aW9uIG91dCBvZiB0aGUgYnVja2V0IHByb3BzXG4gICAqIEBwYXJhbSBwcm9wcyBQYXJcbiAgICovXG4gIHByaXZhdGUgcGFyc2VMaWZlY3ljbGVDb25maWd1cmF0aW9uKCk6IENmbkJ1Y2tldC5MaWZlY3ljbGVDb25maWd1cmF0aW9uUHJvcGVydHkgfCB1bmRlZmluZWQge1xuICAgIGlmICghdGhpcy5saWZlY3ljbGVSdWxlcyB8fCB0aGlzLmxpZmVjeWNsZVJ1bGVzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICBjb25zdCBzZWxmID0gdGhpcztcblxuICAgIHJldHVybiB7IHJ1bGVzOiB0aGlzLmxpZmVjeWNsZVJ1bGVzLm1hcChwYXJzZUxpZmVjeWNsZVJ1bGUpIH07XG5cbiAgICBmdW5jdGlvbiBwYXJzZUxpZmVjeWNsZVJ1bGUocnVsZTogTGlmZWN5Y2xlUnVsZSk6IENmbkJ1Y2tldC5SdWxlUHJvcGVydHkge1xuICAgICAgY29uc3QgZW5hYmxlZCA9IHJ1bGUuZW5hYmxlZCA/PyB0cnVlO1xuXG4gICAgICBjb25zdCB4OiBDZm5CdWNrZXQuUnVsZVByb3BlcnR5ID0ge1xuICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LWxlblxuICAgICAgICBhYm9ydEluY29tcGxldGVNdWx0aXBhcnRVcGxvYWQ6IHJ1bGUuYWJvcnRJbmNvbXBsZXRlTXVsdGlwYXJ0VXBsb2FkQWZ0ZXIgIT09IHVuZGVmaW5lZCA/IHsgZGF5c0FmdGVySW5pdGlhdGlvbjogcnVsZS5hYm9ydEluY29tcGxldGVNdWx0aXBhcnRVcGxvYWRBZnRlci50b0RheXMoKSB9IDogdW5kZWZpbmVkLFxuICAgICAgICBleHBpcmF0aW9uRGF0ZTogcnVsZS5leHBpcmF0aW9uRGF0ZSxcbiAgICAgICAgZXhwaXJhdGlvbkluRGF5czogcnVsZS5leHBpcmF0aW9uPy50b0RheXMoKSxcbiAgICAgICAgaWQ6IHJ1bGUuaWQsXG4gICAgICAgIG5vbmN1cnJlbnRWZXJzaW9uRXhwaXJhdGlvbjogcnVsZS5ub25jdXJyZW50VmVyc2lvbkV4cGlyYXRpb24gJiYge1xuICAgICAgICAgIG5vbmN1cnJlbnREYXlzOiBydWxlLm5vbmN1cnJlbnRWZXJzaW9uRXhwaXJhdGlvbi50b0RheXMoKSxcbiAgICAgICAgICBuZXdlck5vbmN1cnJlbnRWZXJzaW9uczogcnVsZS5ub25jdXJyZW50VmVyc2lvbnNUb1JldGFpbixcbiAgICAgICAgfSxcbiAgICAgICAgbm9uY3VycmVudFZlcnNpb25UcmFuc2l0aW9uczogbWFwT3JVbmRlZmluZWQocnVsZS5ub25jdXJyZW50VmVyc2lvblRyYW5zaXRpb25zLCB0ID0+ICh7XG4gICAgICAgICAgc3RvcmFnZUNsYXNzOiB0LnN0b3JhZ2VDbGFzcy52YWx1ZSxcbiAgICAgICAgICB0cmFuc2l0aW9uSW5EYXlzOiB0LnRyYW5zaXRpb25BZnRlci50b0RheXMoKSxcbiAgICAgICAgICBuZXdlck5vbmN1cnJlbnRWZXJzaW9uczogdC5ub25jdXJyZW50VmVyc2lvbnNUb1JldGFpbixcbiAgICAgICAgfSkpLFxuICAgICAgICBwcmVmaXg6IHJ1bGUucHJlZml4LFxuICAgICAgICBzdGF0dXM6IGVuYWJsZWQgPyAnRW5hYmxlZCcgOiAnRGlzYWJsZWQnLFxuICAgICAgICB0cmFuc2l0aW9uczogbWFwT3JVbmRlZmluZWQocnVsZS50cmFuc2l0aW9ucywgdCA9PiAoe1xuICAgICAgICAgIHN0b3JhZ2VDbGFzczogdC5zdG9yYWdlQ2xhc3MudmFsdWUsXG4gICAgICAgICAgdHJhbnNpdGlvbkRhdGU6IHQudHJhbnNpdGlvbkRhdGUsXG4gICAgICAgICAgdHJhbnNpdGlvbkluRGF5czogdC50cmFuc2l0aW9uQWZ0ZXIgJiYgdC50cmFuc2l0aW9uQWZ0ZXIudG9EYXlzKCksXG4gICAgICAgIH0pKSxcbiAgICAgICAgZXhwaXJlZE9iamVjdERlbGV0ZU1hcmtlcjogcnVsZS5leHBpcmVkT2JqZWN0RGVsZXRlTWFya2VyLFxuICAgICAgICB0YWdGaWx0ZXJzOiBzZWxmLnBhcnNlVGFnRmlsdGVycyhydWxlLnRhZ0ZpbHRlcnMpLFxuICAgICAgICBvYmplY3RTaXplTGVzc1RoYW46IHJ1bGUub2JqZWN0U2l6ZUxlc3NUaGFuLFxuICAgICAgICBvYmplY3RTaXplR3JlYXRlclRoYW46IHJ1bGUub2JqZWN0U2l6ZUdyZWF0ZXJUaGFuLFxuICAgICAgfTtcblxuICAgICAgcmV0dXJuIHg7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVNlcnZlckFjY2Vzc0xvZ3MocHJvcHM6IEJ1Y2tldFByb3BzKTogQ2ZuQnVja2V0LkxvZ2dpbmdDb25maWd1cmF0aW9uUHJvcGVydHkgfCB1bmRlZmluZWQge1xuICAgIGlmICghcHJvcHMuc2VydmVyQWNjZXNzTG9nc0J1Y2tldCAmJiAhcHJvcHMuc2VydmVyQWNjZXNzTG9nc1ByZWZpeCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgZGVzdGluYXRpb25CdWNrZXROYW1lOiBwcm9wcy5zZXJ2ZXJBY2Nlc3NMb2dzQnVja2V0Py5idWNrZXROYW1lLFxuICAgICAgbG9nRmlsZVByZWZpeDogcHJvcHMuc2VydmVyQWNjZXNzTG9nc1ByZWZpeCxcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZU1ldHJpY0NvbmZpZ3VyYXRpb24oKTogQ2ZuQnVja2V0Lk1ldHJpY3NDb25maWd1cmF0aW9uUHJvcGVydHlbXSB8IHVuZGVmaW5lZCB7XG4gICAgaWYgKCF0aGlzLm1ldHJpY3MgfHwgdGhpcy5tZXRyaWNzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICBjb25zdCBzZWxmID0gdGhpcztcblxuICAgIHJldHVybiB0aGlzLm1ldHJpY3MubWFwKHBhcnNlTWV0cmljKTtcblxuICAgIGZ1bmN0aW9uIHBhcnNlTWV0cmljKG1ldHJpYzogQnVja2V0TWV0cmljcyk6IENmbkJ1Y2tldC5NZXRyaWNzQ29uZmlndXJhdGlvblByb3BlcnR5IHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGlkOiBtZXRyaWMuaWQsXG4gICAgICAgIHByZWZpeDogbWV0cmljLnByZWZpeCxcbiAgICAgICAgdGFnRmlsdGVyczogc2VsZi5wYXJzZVRhZ0ZpbHRlcnMobWV0cmljLnRhZ0ZpbHRlcnMpLFxuICAgICAgfTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIHBhcnNlQ29yc0NvbmZpZ3VyYXRpb24oKTogQ2ZuQnVja2V0LkNvcnNDb25maWd1cmF0aW9uUHJvcGVydHkgfCB1bmRlZmluZWQge1xuICAgIGlmICghdGhpcy5jb3JzIHx8IHRoaXMuY29ycy5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIHsgY29yc1J1bGVzOiB0aGlzLmNvcnMubWFwKHBhcnNlQ29ycykgfTtcblxuICAgIGZ1bmN0aW9uIHBhcnNlQ29ycyhydWxlOiBDb3JzUnVsZSk6IENmbkJ1Y2tldC5Db3JzUnVsZVByb3BlcnR5IHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGlkOiBydWxlLmlkLFxuICAgICAgICBtYXhBZ2U6IHJ1bGUubWF4QWdlLFxuICAgICAgICBhbGxvd2VkSGVhZGVyczogcnVsZS5hbGxvd2VkSGVhZGVycyxcbiAgICAgICAgYWxsb3dlZE1ldGhvZHM6IHJ1bGUuYWxsb3dlZE1ldGhvZHMsXG4gICAgICAgIGFsbG93ZWRPcmlnaW5zOiBydWxlLmFsbG93ZWRPcmlnaW5zLFxuICAgICAgICBleHBvc2VkSGVhZGVyczogcnVsZS5leHBvc2VkSGVhZGVycyxcbiAgICAgIH07XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVRhZ0ZpbHRlcnModGFnRmlsdGVycz86IHsgW3RhZzogc3RyaW5nXTogYW55IH0pIHtcbiAgICBpZiAoIXRhZ0ZpbHRlcnMgfHwgdGFnRmlsdGVycy5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKHRhZ0ZpbHRlcnMpLm1hcCh0YWcgPT4gKHtcbiAgICAgIGtleTogdGFnLFxuICAgICAgdmFsdWU6IHRhZ0ZpbHRlcnNbdGFnXSxcbiAgICB9KSk7XG4gIH1cblxuICBwcml2YXRlIHBhcnNlT3duZXJzaGlwQ29udHJvbHMoeyBvYmplY3RPd25lcnNoaXAgfTogQnVja2V0UHJvcHMpOiBDZm5CdWNrZXQuT3duZXJzaGlwQ29udHJvbHNQcm9wZXJ0eSB8IHVuZGVmaW5lZCB7XG4gICAgaWYgKCFvYmplY3RPd25lcnNoaXApIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHJldHVybiB7XG4gICAgICBydWxlczogW3tcbiAgICAgICAgb2JqZWN0T3duZXJzaGlwLFxuICAgICAgfV0sXG4gICAgfTtcbiAgfVxuXG4gIHByaXZhdGUgcGFyc2VUaWVyaW5nQ29uZmlnKHsgaW50ZWxsaWdlbnRUaWVyaW5nQ29uZmlndXJhdGlvbnMgfTogQnVja2V0UHJvcHMpOiBDZm5CdWNrZXQuSW50ZWxsaWdlbnRUaWVyaW5nQ29uZmlndXJhdGlvblByb3BlcnR5W10gfCB1bmRlZmluZWQge1xuICAgIGlmICghaW50ZWxsaWdlbnRUaWVyaW5nQ29uZmlndXJhdGlvbnMpIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIGludGVsbGlnZW50VGllcmluZ0NvbmZpZ3VyYXRpb25zLm1hcChjb25maWcgPT4ge1xuICAgICAgY29uc3QgdGllcmluZ3MgPSBbXTtcbiAgICAgIGlmIChjb25maWcuYXJjaGl2ZUFjY2Vzc1RpZXJUaW1lKSB7XG4gICAgICAgIHRpZXJpbmdzLnB1c2goe1xuICAgICAgICAgIGFjY2Vzc1RpZXI6ICdBUkNISVZFX0FDQ0VTUycsXG4gICAgICAgICAgZGF5czogY29uZmlnLmFyY2hpdmVBY2Nlc3NUaWVyVGltZS50b0RheXMoeyBpbnRlZ3JhbDogdHJ1ZSB9KSxcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBpZiAoY29uZmlnLmRlZXBBcmNoaXZlQWNjZXNzVGllclRpbWUpIHtcbiAgICAgICAgdGllcmluZ3MucHVzaCh7XG4gICAgICAgICAgYWNjZXNzVGllcjogJ0RFRVBfQVJDSElWRV9BQ0NFU1MnLFxuICAgICAgICAgIGRheXM6IGNvbmZpZy5kZWVwQXJjaGl2ZUFjY2Vzc1RpZXJUaW1lLnRvRGF5cyh7IGludGVncmFsOiB0cnVlIH0pLFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB7XG4gICAgICAgIGlkOiBjb25maWcubmFtZSxcbiAgICAgICAgcHJlZml4OiBjb25maWcucHJlZml4LFxuICAgICAgICBzdGF0dXM6ICdFbmFibGVkJyxcbiAgICAgICAgdGFnRmlsdGVyczogY29uZmlnLnRhZ3MsXG4gICAgICAgIHRpZXJpbmdzOiB0aWVyaW5ncyxcbiAgICAgIH07XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIHJlbmRlcldlYnNpdGVDb25maWd1cmF0aW9uKHByb3BzOiBCdWNrZXRQcm9wcyk6IENmbkJ1Y2tldC5XZWJzaXRlQ29uZmlndXJhdGlvblByb3BlcnR5IHwgdW5kZWZpbmVkIHtcbiAgICBpZiAoIXByb3BzLndlYnNpdGVFcnJvckRvY3VtZW50ICYmICFwcm9wcy53ZWJzaXRlSW5kZXhEb2N1bWVudCAmJiAhcHJvcHMud2Vic2l0ZVJlZGlyZWN0ICYmICFwcm9wcy53ZWJzaXRlUm91dGluZ1J1bGVzKSB7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIGlmIChwcm9wcy53ZWJzaXRlRXJyb3JEb2N1bWVudCAmJiAhcHJvcHMud2Vic2l0ZUluZGV4RG9jdW1lbnQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignXCJ3ZWJzaXRlSW5kZXhEb2N1bWVudFwiIGlzIHJlcXVpcmVkIGlmIFwid2Vic2l0ZUVycm9yRG9jdW1lbnRcIiBpcyBzZXQnKTtcbiAgICB9XG5cbiAgICBpZiAocHJvcHMud2Vic2l0ZVJlZGlyZWN0ICYmIChwcm9wcy53ZWJzaXRlRXJyb3JEb2N1bWVudCB8fCBwcm9wcy53ZWJzaXRlSW5kZXhEb2N1bWVudCB8fCBwcm9wcy53ZWJzaXRlUm91dGluZ1J1bGVzKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdcIndlYnNpdGVJbmRleERvY3VtZW50XCIsIFwid2Vic2l0ZUVycm9yRG9jdW1lbnRcIiBhbmQsIFwid2Vic2l0ZVJvdXRpbmdSdWxlc1wiIGNhbm5vdCBiZSBzZXQgaWYgXCJ3ZWJzaXRlUmVkaXJlY3RcIiBpcyB1c2VkJyk7XG4gICAgfVxuXG4gICAgY29uc3Qgcm91dGluZ1J1bGVzID0gcHJvcHMud2Vic2l0ZVJvdXRpbmdSdWxlcyA/IHByb3BzLndlYnNpdGVSb3V0aW5nUnVsZXMubWFwPENmbkJ1Y2tldC5Sb3V0aW5nUnVsZVByb3BlcnR5PigocnVsZSkgPT4ge1xuICAgICAgaWYgKHJ1bGUuY29uZGl0aW9uICYmICFydWxlLmNvbmRpdGlvbi5odHRwRXJyb3JDb2RlUmV0dXJuZWRFcXVhbHMgJiYgIXJ1bGUuY29uZGl0aW9uLmtleVByZWZpeEVxdWFscykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RoZSBjb25kaXRpb24gcHJvcGVydHkgY2Fubm90IGJlIGFuIGVtcHR5IG9iamVjdCcpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICByZWRpcmVjdFJ1bGU6IHtcbiAgICAgICAgICBob3N0TmFtZTogcnVsZS5ob3N0TmFtZSxcbiAgICAgICAgICBodHRwUmVkaXJlY3RDb2RlOiBydWxlLmh0dHBSZWRpcmVjdENvZGUsXG4gICAgICAgICAgcHJvdG9jb2w6IHJ1bGUucHJvdG9jb2wsXG4gICAgICAgICAgcmVwbGFjZUtleVdpdGg6IHJ1bGUucmVwbGFjZUtleSAmJiBydWxlLnJlcGxhY2VLZXkud2l0aEtleSxcbiAgICAgICAgICByZXBsYWNlS2V5UHJlZml4V2l0aDogcnVsZS5yZXBsYWNlS2V5ICYmIHJ1bGUucmVwbGFjZUtleS5wcmVmaXhXaXRoS2V5LFxuICAgICAgICB9LFxuICAgICAgICByb3V0aW5nUnVsZUNvbmRpdGlvbjogcnVsZS5jb25kaXRpb24sXG4gICAgICB9O1xuICAgIH0pIDogdW5kZWZpbmVkO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGluZGV4RG9jdW1lbnQ6IHByb3BzLndlYnNpdGVJbmRleERvY3VtZW50LFxuICAgICAgZXJyb3JEb2N1bWVudDogcHJvcHMud2Vic2l0ZUVycm9yRG9jdW1lbnQsXG4gICAgICByZWRpcmVjdEFsbFJlcXVlc3RzVG86IHByb3BzLndlYnNpdGVSZWRpcmVjdCxcbiAgICAgIHJvdXRpbmdSdWxlcyxcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEFsbG93cyB0aGUgTG9nRGVsaXZlcnkgZ3JvdXAgdG8gd3JpdGUsIGZhaWxzIGlmIEFDTCB3YXMgc2V0IGRpZmZlcmVudGx5LlxuICAgKlxuICAgKiBAc2VlXG4gICAqIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25TMy9sYXRlc3QvZGV2L2FjbC1vdmVydmlldy5odG1sI2Nhbm5lZC1hY2xcbiAgICovXG4gIHByaXZhdGUgYWxsb3dMb2dEZWxpdmVyeSgpIHtcbiAgICBpZiAodGhpcy5hY2Nlc3NDb250cm9sICYmIHRoaXMuYWNjZXNzQ29udHJvbCAhPT0gQnVja2V0QWNjZXNzQ29udHJvbC5MT0dfREVMSVZFUllfV1JJVEUpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkNhbm5vdCBlbmFibGUgbG9nIGRlbGl2ZXJ5IHRvIHRoaXMgYnVja2V0IGJlY2F1c2UgdGhlIGJ1Y2tldCdzIEFDTCBoYXMgYmVlbiBzZXQgYW5kIGNhbid0IGJlIGNoYW5nZWRcIik7XG4gICAgfVxuXG4gICAgdGhpcy5hY2Nlc3NDb250cm9sID0gQnVja2V0QWNjZXNzQ29udHJvbC5MT0dfREVMSVZFUllfV1JJVEU7XG4gIH1cblxuICBwcml2YXRlIHBhcnNlSW52ZW50b3J5Q29uZmlndXJhdGlvbigpOiBDZm5CdWNrZXQuSW52ZW50b3J5Q29uZmlndXJhdGlvblByb3BlcnR5W10gfCB1bmRlZmluZWQge1xuICAgIGlmICghdGhpcy5pbnZlbnRvcmllcyB8fCB0aGlzLmludmVudG9yaWVzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5pbnZlbnRvcmllcy5tYXAoKGludmVudG9yeSwgaW5kZXgpID0+IHtcbiAgICAgIGNvbnN0IGZvcm1hdCA9IGludmVudG9yeS5mb3JtYXQgPz8gSW52ZW50b3J5Rm9ybWF0LkNTVjtcbiAgICAgIGNvbnN0IGZyZXF1ZW5jeSA9IGludmVudG9yeS5mcmVxdWVuY3kgPz8gSW52ZW50b3J5RnJlcXVlbmN5LldFRUtMWTtcbiAgICAgIGNvbnN0IGlkID0gaW52ZW50b3J5LmludmVudG9yeUlkID8/IGAke3RoaXMubm9kZS5pZH1JbnZlbnRvcnkke2luZGV4fWA7XG5cbiAgICAgIGlmIChpbnZlbnRvcnkuZGVzdGluYXRpb24uYnVja2V0IGluc3RhbmNlb2YgQnVja2V0KSB7XG4gICAgICAgIGludmVudG9yeS5kZXN0aW5hdGlvbi5idWNrZXQuYWRkVG9SZXNvdXJjZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgICAgIGFjdGlvbnM6IFsnczM6UHV0T2JqZWN0J10sXG4gICAgICAgICAgcmVzb3VyY2VzOiBbXG4gICAgICAgICAgICBpbnZlbnRvcnkuZGVzdGluYXRpb24uYnVja2V0LmJ1Y2tldEFybixcbiAgICAgICAgICAgIGludmVudG9yeS5kZXN0aW5hdGlvbi5idWNrZXQuYXJuRm9yT2JqZWN0cyhgJHtpbnZlbnRvcnkuZGVzdGluYXRpb24ucHJlZml4ID8/ICcnfSpgKSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHByaW5jaXBhbHM6IFtuZXcgaWFtLlNlcnZpY2VQcmluY2lwYWwoJ3MzLmFtYXpvbmF3cy5jb20nKV0sXG4gICAgICAgICAgY29uZGl0aW9uczoge1xuICAgICAgICAgICAgQXJuTGlrZToge1xuICAgICAgICAgICAgICAnYXdzOlNvdXJjZUFybic6IHRoaXMuYnVja2V0QXJuLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9KSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB7XG4gICAgICAgIGlkLFxuICAgICAgICBkZXN0aW5hdGlvbjoge1xuICAgICAgICAgIGJ1Y2tldEFybjogaW52ZW50b3J5LmRlc3RpbmF0aW9uLmJ1Y2tldC5idWNrZXRBcm4sXG4gICAgICAgICAgYnVja2V0QWNjb3VudElkOiBpbnZlbnRvcnkuZGVzdGluYXRpb24uYnVja2V0T3duZXIsXG4gICAgICAgICAgcHJlZml4OiBpbnZlbnRvcnkuZGVzdGluYXRpb24ucHJlZml4LFxuICAgICAgICAgIGZvcm1hdCxcbiAgICAgICAgfSxcbiAgICAgICAgZW5hYmxlZDogaW52ZW50b3J5LmVuYWJsZWQgPz8gdHJ1ZSxcbiAgICAgICAgaW5jbHVkZWRPYmplY3RWZXJzaW9uczogaW52ZW50b3J5LmluY2x1ZGVPYmplY3RWZXJzaW9ucyA/PyBJbnZlbnRvcnlPYmplY3RWZXJzaW9uLkFMTCxcbiAgICAgICAgc2NoZWR1bGVGcmVxdWVuY3k6IGZyZXF1ZW5jeSxcbiAgICAgICAgb3B0aW9uYWxGaWVsZHM6IGludmVudG9yeS5vcHRpb25hbEZpZWxkcyxcbiAgICAgICAgcHJlZml4OiBpbnZlbnRvcnkub2JqZWN0c1ByZWZpeCxcbiAgICAgIH07XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGVuYWJsZUF1dG9EZWxldGVPYmplY3RzKCkge1xuICAgIGNvbnN0IHByb3ZpZGVyID0gQ3VzdG9tUmVzb3VyY2VQcm92aWRlci5nZXRPckNyZWF0ZVByb3ZpZGVyKHRoaXMsIEFVVE9fREVMRVRFX09CSkVDVFNfUkVTT1VSQ0VfVFlQRSwge1xuICAgICAgY29kZURpcmVjdG9yeTogcGF0aC5qb2luKF9fZGlybmFtZSwgJ2F1dG8tZGVsZXRlLW9iamVjdHMtaGFuZGxlcicpLFxuICAgICAgcnVudGltZTogQ3VzdG9tUmVzb3VyY2VQcm92aWRlclJ1bnRpbWUuTk9ERUpTXzE0X1gsXG4gICAgICBkZXNjcmlwdGlvbjogYExhbWJkYSBmdW5jdGlvbiBmb3IgYXV0by1kZWxldGluZyBvYmplY3RzIGluICR7dGhpcy5idWNrZXROYW1lfSBTMyBidWNrZXQuYCxcbiAgICB9KTtcblxuICAgIC8vIFVzZSBhIGJ1Y2tldCBwb2xpY3kgdG8gYWxsb3cgdGhlIGN1c3RvbSByZXNvdXJjZSB0byBkZWxldGVcbiAgICAvLyBvYmplY3RzIGluIHRoZSBidWNrZXRcbiAgICB0aGlzLmFkZFRvUmVzb3VyY2VQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgYWN0aW9uczogW1xuICAgICAgICAvLyBsaXN0IG9iamVjdHNcbiAgICAgICAgLi4ucGVybXMuQlVDS0VUX1JFQURfTUVUQURBVEFfQUNUSU9OUyxcbiAgICAgICAgLi4ucGVybXMuQlVDS0VUX0RFTEVURV9BQ1RJT05TLCAvLyBhbmQgdGhlbiBkZWxldGUgdGhlbVxuICAgICAgXSxcbiAgICAgIHJlc291cmNlczogW1xuICAgICAgICB0aGlzLmJ1Y2tldEFybixcbiAgICAgICAgdGhpcy5hcm5Gb3JPYmplY3RzKCcqJyksXG4gICAgICBdLFxuICAgICAgcHJpbmNpcGFsczogW25ldyBpYW0uQXJuUHJpbmNpcGFsKHByb3ZpZGVyLnJvbGVBcm4pXSxcbiAgICB9KSk7XG5cbiAgICBjb25zdCBjdXN0b21SZXNvdXJjZSA9IG5ldyBDdXN0b21SZXNvdXJjZSh0aGlzLCAnQXV0b0RlbGV0ZU9iamVjdHNDdXN0b21SZXNvdXJjZScsIHtcbiAgICAgIHJlc291cmNlVHlwZTogQVVUT19ERUxFVEVfT0JKRUNUU19SRVNPVVJDRV9UWVBFLFxuICAgICAgc2VydmljZVRva2VuOiBwcm92aWRlci5zZXJ2aWNlVG9rZW4sXG4gICAgICBwcm9wZXJ0aWVzOiB7XG4gICAgICAgIEJ1Y2tldE5hbWU6IHRoaXMuYnVja2V0TmFtZSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBFbnN1cmUgYnVja2V0IHBvbGljeSBpcyBkZWxldGVkIEFGVEVSIHRoZSBjdXN0b20gcmVzb3VyY2Ugb3RoZXJ3aXNlXG4gICAgLy8gd2UgZG9uJ3QgaGF2ZSBwZXJtaXNzaW9ucyB0byBsaXN0IGFuZCBkZWxldGUgaW4gdGhlIGJ1Y2tldC5cbiAgICAvLyAoYWRkIGEgYGlmYCB0byBtYWtlIFRTIGhhcHB5KVxuICAgIGlmICh0aGlzLnBvbGljeSkge1xuICAgICAgY3VzdG9tUmVzb3VyY2Uubm9kZS5hZGREZXBlbmRlbmN5KHRoaXMucG9saWN5KTtcbiAgICB9XG5cbiAgICAvLyBXZSBhbHNvIHRhZyB0aGUgYnVja2V0IHRvIHJlY29yZCB0aGUgZmFjdCB0aGF0IHdlIHdhbnQgaXQgYXV0b2RlbGV0ZWQuXG4gICAgLy8gVGhlIGN1c3RvbSByZXNvdXJjZSB3aWxsIGNoZWNrIHRoaXMgdGFnIGJlZm9yZSBhY3R1YWxseSBkb2luZyB0aGUgZGVsZXRlLlxuICAgIC8vIEJlY2F1c2UgdGFnZ2luZyBhbmQgdW50YWdnaW5nIHdpbGwgQUxXQVlTIGhhcHBlbiBiZWZvcmUgdGhlIENSIGlzIGRlbGV0ZWQsXG4gICAgLy8gd2UgY2FuIHNldCBgYXV0b0RlbGV0ZU9iamVjdHM6IGZhbHNlYCB3aXRob3V0IHRoZSByZW1vdmFsIG9mIHRoZSBDUiBlbXB0eWluZ1xuICAgIC8vIHRoZSBidWNrZXQgYXMgYSBzaWRlIGVmZmVjdC5cbiAgICBUYWdzLm9mKHRoaXMuX3Jlc291cmNlKS5hZGQoQVVUT19ERUxFVEVfT0JKRUNUU19UQUcsICd0cnVlJyk7XG4gIH1cbn1cblxuLyoqXG4gKiBXaGF0IGtpbmQgb2Ygc2VydmVyLXNpZGUgZW5jcnlwdGlvbiB0byBhcHBseSB0byB0aGlzIGJ1Y2tldFxuICovXG5leHBvcnQgZW51bSBCdWNrZXRFbmNyeXB0aW9uIHtcbiAgLyoqXG4gICAqIE9iamVjdHMgaW4gdGhlIGJ1Y2tldCBhcmUgbm90IGVuY3J5cHRlZC5cbiAgICovXG4gIFVORU5DUllQVEVEID0gJ05PTkUnLFxuXG4gIC8qKlxuICAgKiBTZXJ2ZXItc2lkZSBLTVMgZW5jcnlwdGlvbiB3aXRoIGEgbWFzdGVyIGtleSBtYW5hZ2VkIGJ5IEtNUy5cbiAgICovXG4gIEtNU19NQU5BR0VEID0gJ01BTkFHRUQnLFxuXG4gIC8qKlxuICAgKiBTZXJ2ZXItc2lkZSBlbmNyeXB0aW9uIHdpdGggYSBtYXN0ZXIga2V5IG1hbmFnZWQgYnkgUzMuXG4gICAqL1xuICBTM19NQU5BR0VEID0gJ1MzTUFOQUdFRCcsXG5cbiAgLyoqXG4gICAqIFNlcnZlci1zaWRlIGVuY3J5cHRpb24gd2l0aCBhIEtNUyBrZXkgbWFuYWdlZCBieSB0aGUgdXNlci5cbiAgICogSWYgYGVuY3J5cHRpb25LZXlgIGlzIHNwZWNpZmllZCwgdGhpcyBrZXkgd2lsbCBiZSB1c2VkLCBvdGhlcndpc2UsIG9uZSB3aWxsIGJlIGRlZmluZWQuXG4gICAqL1xuICBLTVMgPSAnS01TJyxcbn1cblxuLyoqXG4gKiBOb3RpZmljYXRpb24gZXZlbnQgdHlwZXMuXG4gKiBAbGluayBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L3VzZXJndWlkZS9ub3RpZmljYXRpb24taG93LXRvLWV2ZW50LXR5cGVzLWFuZC1kZXN0aW5hdGlvbnMuaHRtbCNzdXBwb3J0ZWQtbm90aWZpY2F0aW9uLWV2ZW50LXR5cGVzXG4gKi9cbmV4cG9ydCBlbnVtIEV2ZW50VHlwZSB7XG4gIC8qKlxuICAgKiBBbWF6b24gUzMgQVBJcyBzdWNoIGFzIFBVVCwgUE9TVCwgYW5kIENPUFkgY2FuIGNyZWF0ZSBhbiBvYmplY3QuIFVzaW5nXG4gICAqIHRoZXNlIGV2ZW50IHR5cGVzLCB5b3UgY2FuIGVuYWJsZSBub3RpZmljYXRpb24gd2hlbiBhbiBvYmplY3QgaXMgY3JlYXRlZFxuICAgKiB1c2luZyBhIHNwZWNpZmljIEFQSSwgb3IgeW91IGNhbiB1c2UgdGhlIHMzOk9iamVjdENyZWF0ZWQ6KiBldmVudCB0eXBlIHRvXG4gICAqIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHJlZ2FyZGxlc3Mgb2YgdGhlIEFQSSB0aGF0IHdhcyB1c2VkIHRvIGNyZWF0ZSBhblxuICAgKiBvYmplY3QuXG4gICAqL1xuICBPQkpFQ1RfQ1JFQVRFRCA9ICdzMzpPYmplY3RDcmVhdGVkOionLFxuXG4gIC8qKlxuICAgKiBBbWF6b24gUzMgQVBJcyBzdWNoIGFzIFBVVCwgUE9TVCwgYW5kIENPUFkgY2FuIGNyZWF0ZSBhbiBvYmplY3QuIFVzaW5nXG4gICAqIHRoZXNlIGV2ZW50IHR5cGVzLCB5b3UgY2FuIGVuYWJsZSBub3RpZmljYXRpb24gd2hlbiBhbiBvYmplY3QgaXMgY3JlYXRlZFxuICAgKiB1c2luZyBhIHNwZWNpZmljIEFQSSwgb3IgeW91IGNhbiB1c2UgdGhlIHMzOk9iamVjdENyZWF0ZWQ6KiBldmVudCB0eXBlIHRvXG4gICAqIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHJlZ2FyZGxlc3Mgb2YgdGhlIEFQSSB0aGF0IHdhcyB1c2VkIHRvIGNyZWF0ZSBhblxuICAgKiBvYmplY3QuXG4gICAqL1xuICBPQkpFQ1RfQ1JFQVRFRF9QVVQgPSAnczM6T2JqZWN0Q3JlYXRlZDpQdXQnLFxuXG4gIC8qKlxuICAgKiBBbWF6b24gUzMgQVBJcyBzdWNoIGFzIFBVVCwgUE9TVCwgYW5kIENPUFkgY2FuIGNyZWF0ZSBhbiBvYmplY3QuIFVzaW5nXG4gICAqIHRoZXNlIGV2ZW50IHR5cGVzLCB5b3UgY2FuIGVuYWJsZSBub3RpZmljYXRpb24gd2hlbiBhbiBvYmplY3QgaXMgY3JlYXRlZFxuICAgKiB1c2luZyBhIHNwZWNpZmljIEFQSSwgb3IgeW91IGNhbiB1c2UgdGhlIHMzOk9iamVjdENyZWF0ZWQ6KiBldmVudCB0eXBlIHRvXG4gICAqIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHJlZ2FyZGxlc3Mgb2YgdGhlIEFQSSB0aGF0IHdhcyB1c2VkIHRvIGNyZWF0ZSBhblxuICAgKiBvYmplY3QuXG4gICAqL1xuICBPQkpFQ1RfQ1JFQVRFRF9QT1NUID0gJ3MzOk9iamVjdENyZWF0ZWQ6UG9zdCcsXG5cbiAgLyoqXG4gICAqIEFtYXpvbiBTMyBBUElzIHN1Y2ggYXMgUFVULCBQT1NULCBhbmQgQ09QWSBjYW4gY3JlYXRlIGFuIG9iamVjdC4gVXNpbmdcbiAgICogdGhlc2UgZXZlbnQgdHlwZXMsIHlvdSBjYW4gZW5hYmxlIG5vdGlmaWNhdGlvbiB3aGVuIGFuIG9iamVjdCBpcyBjcmVhdGVkXG4gICAqIHVzaW5nIGEgc3BlY2lmaWMgQVBJLCBvciB5b3UgY2FuIHVzZSB0aGUgczM6T2JqZWN0Q3JlYXRlZDoqIGV2ZW50IHR5cGUgdG9cbiAgICogcmVxdWVzdCBub3RpZmljYXRpb24gcmVnYXJkbGVzcyBvZiB0aGUgQVBJIHRoYXQgd2FzIHVzZWQgdG8gY3JlYXRlIGFuXG4gICAqIG9iamVjdC5cbiAgICovXG4gIE9CSkVDVF9DUkVBVEVEX0NPUFkgPSAnczM6T2JqZWN0Q3JlYXRlZDpDb3B5JyxcblxuICAvKipcbiAgICogQW1hem9uIFMzIEFQSXMgc3VjaCBhcyBQVVQsIFBPU1QsIGFuZCBDT1BZIGNhbiBjcmVhdGUgYW4gb2JqZWN0LiBVc2luZ1xuICAgKiB0aGVzZSBldmVudCB0eXBlcywgeW91IGNhbiBlbmFibGUgbm90aWZpY2F0aW9uIHdoZW4gYW4gb2JqZWN0IGlzIGNyZWF0ZWRcbiAgICogdXNpbmcgYSBzcGVjaWZpYyBBUEksIG9yIHlvdSBjYW4gdXNlIHRoZSBzMzpPYmplY3RDcmVhdGVkOiogZXZlbnQgdHlwZSB0b1xuICAgKiByZXF1ZXN0IG5vdGlmaWNhdGlvbiByZWdhcmRsZXNzIG9mIHRoZSBBUEkgdGhhdCB3YXMgdXNlZCB0byBjcmVhdGUgYW5cbiAgICogb2JqZWN0LlxuICAgKi9cbiAgT0JKRUNUX0NSRUFURURfQ09NUExFVEVfTVVMVElQQVJUX1VQTE9BRCA9ICdzMzpPYmplY3RDcmVhdGVkOkNvbXBsZXRlTXVsdGlwYXJ0VXBsb2FkJyxcblxuICAvKipcbiAgICogQnkgdXNpbmcgdGhlIE9iamVjdFJlbW92ZWQgZXZlbnQgdHlwZXMsIHlvdSBjYW4gZW5hYmxlIG5vdGlmaWNhdGlvbiB3aGVuXG4gICAqIGFuIG9iamVjdCBvciBhIGJhdGNoIG9mIG9iamVjdHMgaXMgcmVtb3ZlZCBmcm9tIGEgYnVja2V0LlxuICAgKlxuICAgKiBZb3UgY2FuIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHdoZW4gYW4gb2JqZWN0IGlzIGRlbGV0ZWQgb3IgYSB2ZXJzaW9uZWRcbiAgICogb2JqZWN0IGlzIHBlcm1hbmVudGx5IGRlbGV0ZWQgYnkgdXNpbmcgdGhlIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlIGV2ZW50XG4gICAqIHR5cGUuIE9yIHlvdSBjYW4gcmVxdWVzdCBub3RpZmljYXRpb24gd2hlbiBhIGRlbGV0ZSBtYXJrZXIgaXMgY3JlYXRlZCBmb3JcbiAgICogYSB2ZXJzaW9uZWQgb2JqZWN0IGJ5IHVzaW5nIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlTWFya2VyQ3JlYXRlZC4gRm9yXG4gICAqIGluZm9ybWF0aW9uIGFib3V0IGRlbGV0aW5nIHZlcnNpb25lZCBvYmplY3RzLCBzZWUgRGVsZXRpbmcgT2JqZWN0XG4gICAqIFZlcnNpb25zLiBZb3UgY2FuIGFsc28gdXNlIGEgd2lsZGNhcmQgczM6T2JqZWN0UmVtb3ZlZDoqIHRvIHJlcXVlc3RcbiAgICogbm90aWZpY2F0aW9uIGFueXRpbWUgYW4gb2JqZWN0IGlzIGRlbGV0ZWQuXG4gICAqXG4gICAqIFlvdSB3aWxsIG5vdCByZWNlaXZlIGV2ZW50IG5vdGlmaWNhdGlvbnMgZnJvbSBhdXRvbWF0aWMgZGVsZXRlcyBmcm9tXG4gICAqIGxpZmVjeWNsZSBwb2xpY2llcyBvciBmcm9tIGZhaWxlZCBvcGVyYXRpb25zLlxuICAgKi9cbiAgT0JKRUNUX1JFTU9WRUQgPSAnczM6T2JqZWN0UmVtb3ZlZDoqJyxcblxuICAvKipcbiAgICogQnkgdXNpbmcgdGhlIE9iamVjdFJlbW92ZWQgZXZlbnQgdHlwZXMsIHlvdSBjYW4gZW5hYmxlIG5vdGlmaWNhdGlvbiB3aGVuXG4gICAqIGFuIG9iamVjdCBvciBhIGJhdGNoIG9mIG9iamVjdHMgaXMgcmVtb3ZlZCBmcm9tIGEgYnVja2V0LlxuICAgKlxuICAgKiBZb3UgY2FuIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHdoZW4gYW4gb2JqZWN0IGlzIGRlbGV0ZWQgb3IgYSB2ZXJzaW9uZWRcbiAgICogb2JqZWN0IGlzIHBlcm1hbmVudGx5IGRlbGV0ZWQgYnkgdXNpbmcgdGhlIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlIGV2ZW50XG4gICAqIHR5cGUuIE9yIHlvdSBjYW4gcmVxdWVzdCBub3RpZmljYXRpb24gd2hlbiBhIGRlbGV0ZSBtYXJrZXIgaXMgY3JlYXRlZCBmb3JcbiAgICogYSB2ZXJzaW9uZWQgb2JqZWN0IGJ5IHVzaW5nIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlTWFya2VyQ3JlYXRlZC4gRm9yXG4gICAqIGluZm9ybWF0aW9uIGFib3V0IGRlbGV0aW5nIHZlcnNpb25lZCBvYmplY3RzLCBzZWUgRGVsZXRpbmcgT2JqZWN0XG4gICAqIFZlcnNpb25zLiBZb3UgY2FuIGFsc28gdXNlIGEgd2lsZGNhcmQgczM6T2JqZWN0UmVtb3ZlZDoqIHRvIHJlcXVlc3RcbiAgICogbm90aWZpY2F0aW9uIGFueXRpbWUgYW4gb2JqZWN0IGlzIGRlbGV0ZWQuXG4gICAqXG4gICAqIFlvdSB3aWxsIG5vdCByZWNlaXZlIGV2ZW50IG5vdGlmaWNhdGlvbnMgZnJvbSBhdXRvbWF0aWMgZGVsZXRlcyBmcm9tXG4gICAqIGxpZmVjeWNsZSBwb2xpY2llcyBvciBmcm9tIGZhaWxlZCBvcGVyYXRpb25zLlxuICAgKi9cbiAgT0JKRUNUX1JFTU9WRURfREVMRVRFID0gJ3MzOk9iamVjdFJlbW92ZWQ6RGVsZXRlJyxcblxuICAvKipcbiAgICogQnkgdXNpbmcgdGhlIE9iamVjdFJlbW92ZWQgZXZlbnQgdHlwZXMsIHlvdSBjYW4gZW5hYmxlIG5vdGlmaWNhdGlvbiB3aGVuXG4gICAqIGFuIG9iamVjdCBvciBhIGJhdGNoIG9mIG9iamVjdHMgaXMgcmVtb3ZlZCBmcm9tIGEgYnVja2V0LlxuICAgKlxuICAgKiBZb3UgY2FuIHJlcXVlc3Qgbm90aWZpY2F0aW9uIHdoZW4gYW4gb2JqZWN0IGlzIGRlbGV0ZWQgb3IgYSB2ZXJzaW9uZWRcbiAgICogb2JqZWN0IGlzIHBlcm1hbmVudGx5IGRlbGV0ZWQgYnkgdXNpbmcgdGhlIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlIGV2ZW50XG4gICAqIHR5cGUuIE9yIHlvdSBjYW4gcmVxdWVzdCBub3RpZmljYXRpb24gd2hlbiBhIGRlbGV0ZSBtYXJrZXIgaXMgY3JlYXRlZCBmb3JcbiAgICogYSB2ZXJzaW9uZWQgb2JqZWN0IGJ5IHVzaW5nIHMzOk9iamVjdFJlbW92ZWQ6RGVsZXRlTWFya2VyQ3JlYXRlZC4gRm9yXG4gICAqIGluZm9ybWF0aW9uIGFib3V0IGRlbGV0aW5nIHZlcnNpb25lZCBvYmplY3RzLCBzZWUgRGVsZXRpbmcgT2JqZWN0XG4gICAqIFZlcnNpb25zLiBZb3UgY2FuIGFsc28gdXNlIGEgd2lsZGNhcmQgczM6T2JqZWN0UmVtb3ZlZDoqIHRvIHJlcXVlc3RcbiAgICogbm90aWZpY2F0aW9uIGFueXRpbWUgYW4gb2JqZWN0IGlzIGRlbGV0ZWQuXG4gICAqXG4gICAqIFlvdSB3aWxsIG5vdCByZWNlaXZlIGV2ZW50IG5vdGlmaWNhdGlvbnMgZnJvbSBhdXRvbWF0aWMgZGVsZXRlcyBmcm9tXG4gICAqIGxpZmVjeWNsZSBwb2xpY2llcyBvciBmcm9tIGZhaWxlZCBvcGVyYXRpb25zLlxuICAgKi9cbiAgT0JKRUNUX1JFTU9WRURfREVMRVRFX01BUktFUl9DUkVBVEVEID0gJ3MzOk9iamVjdFJlbW92ZWQ6RGVsZXRlTWFya2VyQ3JlYXRlZCcsXG5cbiAgLyoqXG4gICAqIFVzaW5nIHJlc3RvcmUgb2JqZWN0IGV2ZW50IHR5cGVzIHlvdSBjYW4gcmVjZWl2ZSBub3RpZmljYXRpb25zIGZvclxuICAgKiBpbml0aWF0aW9uIGFuZCBjb21wbGV0aW9uIHdoZW4gcmVzdG9yaW5nIG9iamVjdHMgZnJvbSB0aGUgUzMgR2xhY2llclxuICAgKiBzdG9yYWdlIGNsYXNzLlxuICAgKlxuICAgKiBZb3UgdXNlIHMzOk9iamVjdFJlc3RvcmU6UG9zdCB0byByZXF1ZXN0IG5vdGlmaWNhdGlvbiBvZiBvYmplY3QgcmVzdG9yYXRpb25cbiAgICogaW5pdGlhdGlvbi5cbiAgICovXG4gIE9CSkVDVF9SRVNUT1JFX1BPU1QgPSAnczM6T2JqZWN0UmVzdG9yZTpQb3N0JyxcblxuICAvKipcbiAgICogVXNpbmcgcmVzdG9yZSBvYmplY3QgZXZlbnQgdHlwZXMgeW91IGNhbiByZWNlaXZlIG5vdGlmaWNhdGlvbnMgZm9yXG4gICAqIGluaXRpYXRpb24gYW5kIGNvbXBsZXRpb24gd2hlbiByZXN0b3Jpbmcgb2JqZWN0cyBmcm9tIHRoZSBTMyBHbGFjaWVyXG4gICAqIHN0b3JhZ2UgY2xhc3MuXG4gICAqXG4gICAqIFlvdSB1c2UgczM6T2JqZWN0UmVzdG9yZTpDb21wbGV0ZWQgdG8gcmVxdWVzdCBub3RpZmljYXRpb24gb2ZcbiAgICogcmVzdG9yYXRpb24gY29tcGxldGlvbi5cbiAgICovXG4gIE9CSkVDVF9SRVNUT1JFX0NPTVBMRVRFRCA9ICdzMzpPYmplY3RSZXN0b3JlOkNvbXBsZXRlZCcsXG5cbiAgLyoqXG4gICAqIFVzaW5nIHJlc3RvcmUgb2JqZWN0IGV2ZW50IHR5cGVzIHlvdSBjYW4gcmVjZWl2ZSBub3RpZmljYXRpb25zIGZvclxuICAgKiBpbml0aWF0aW9uIGFuZCBjb21wbGV0aW9uIHdoZW4gcmVzdG9yaW5nIG9iamVjdHMgZnJvbSB0aGUgUzMgR2xhY2llclxuICAgKiBzdG9yYWdlIGNsYXNzLlxuICAgKlxuICAgKiBZb3UgdXNlIHMzOk9iamVjdFJlc3RvcmU6RGVsZXRlIHRvIHJlcXVlc3Qgbm90aWZpY2F0aW9uIG9mXG4gICAqIHJlc3RvcmF0aW9uIGNvbXBsZXRpb24uXG4gICAqL1xuICBPQkpFQ1RfUkVTVE9SRV9ERUxFVEUgPSAnczM6T2JqZWN0UmVzdG9yZTpEZWxldGUnLFxuXG4gIC8qKlxuICAgKiBZb3UgY2FuIHVzZSB0aGlzIGV2ZW50IHR5cGUgdG8gcmVxdWVzdCBBbWF6b24gUzMgdG8gc2VuZCBhIG5vdGlmaWNhdGlvblxuICAgKiBtZXNzYWdlIHdoZW4gQW1hem9uIFMzIGRldGVjdHMgdGhhdCBhbiBvYmplY3Qgb2YgdGhlIFJSUyBzdG9yYWdlIGNsYXNzIGlzXG4gICAqIGxvc3QuXG4gICAqL1xuICBSRURVQ0VEX1JFRFVOREFOQ1lfTE9TVF9PQkpFQ1QgPSAnczM6UmVkdWNlZFJlZHVuZGFuY3lMb3N0T2JqZWN0JyxcblxuICAvKipcbiAgICogWW91IHJlY2VpdmUgdGhpcyBub3RpZmljYXRpb24gZXZlbnQgd2hlbiBhbiBvYmplY3QgdGhhdCB3YXMgZWxpZ2libGUgZm9yXG4gICAqIHJlcGxpY2F0aW9uIHVzaW5nIEFtYXpvbiBTMyBSZXBsaWNhdGlvbiBUaW1lIENvbnRyb2wgZmFpbGVkIHRvIHJlcGxpY2F0ZS5cbiAgICovXG4gIFJFUExJQ0FUSU9OX09QRVJBVElPTl9GQUlMRURfUkVQTElDQVRJT04gPSAnczM6UmVwbGljYXRpb246T3BlcmF0aW9uRmFpbGVkUmVwbGljYXRpb24nLFxuXG4gIC8qKlxuICAgKiBZb3UgcmVjZWl2ZSB0aGlzIG5vdGlmaWNhdGlvbiBldmVudCB3aGVuIGFuIG9iamVjdCB0aGF0IHdhcyBlbGlnaWJsZSBmb3JcbiAgICogcmVwbGljYXRpb24gdXNpbmcgQW1hem9uIFMzIFJlcGxpY2F0aW9uIFRpbWUgQ29udHJvbCBleGNlZWRlZCB0aGUgMTUtbWludXRlXG4gICAqIHRocmVzaG9sZCBmb3IgcmVwbGljYXRpb24uXG4gICAqL1xuICBSRVBMSUNBVElPTl9PUEVSQVRJT05fTUlTU0VEX1RIUkVTSE9MRCA9ICdzMzpSZXBsaWNhdGlvbjpPcGVyYXRpb25NaXNzZWRUaHJlc2hvbGQnLFxuXG4gIC8qKlxuICAgKiBZb3UgcmVjZWl2ZSB0aGlzIG5vdGlmaWNhdGlvbiBldmVudCBmb3IgYW4gb2JqZWN0IHRoYXQgd2FzIGVsaWdpYmxlIGZvclxuICAgKiByZXBsaWNhdGlvbiB1c2luZyB0aGUgQW1hem9uIFMzIFJlcGxpY2F0aW9uIFRpbWUgQ29udHJvbCBmZWF0dXJlIHJlcGxpY2F0ZWRcbiAgICogYWZ0ZXIgdGhlIDE1LW1pbnV0ZSB0aHJlc2hvbGQuXG4gICAqL1xuICBSRVBMSUNBVElPTl9PUEVSQVRJT05fUkVQTElDQVRFRF9BRlRFUl9USFJFU0hPTEQgPSAnczM6UmVwbGljYXRpb246T3BlcmF0aW9uUmVwbGljYXRlZEFmdGVyVGhyZXNob2xkJyxcblxuICAvKipcbiAgICogWW91IHJlY2VpdmUgdGhpcyBub3RpZmljYXRpb24gZXZlbnQgZm9yIGFuIG9iamVjdCB0aGF0IHdhcyBlbGlnaWJsZSBmb3JcbiAgICogcmVwbGljYXRpb24gdXNpbmcgQW1hem9uIFMzIFJlcGxpY2F0aW9uIFRpbWUgQ29udHJvbCBidXQgaXMgbm8gbG9uZ2VyIHRyYWNrZWRcbiAgICogYnkgcmVwbGljYXRpb24gbWV0cmljcy5cbiAgICovXG4gIFJFUExJQ0FUSU9OX09QRVJBVElPTl9OT1RfVFJBQ0tFRCA9ICdzMzpSZXBsaWNhdGlvbjpPcGVyYXRpb25Ob3RUcmFja2VkJyxcblxuICAvKipcbiAgICogQnkgdXNpbmcgdGhlIExpZmVjeWNsZUV4cGlyYXRpb24gZXZlbnQgdHlwZXMsIHlvdSBjYW4gcmVjZWl2ZSBhIG5vdGlmaWNhdGlvblxuICAgKiB3aGVuIEFtYXpvbiBTMyBkZWxldGVzIGFuIG9iamVjdCBiYXNlZCBvbiB5b3VyIFMzIExpZmVjeWNsZSBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgTElGRUNZQ0xFX0VYUElSQVRJT04gPSAnczM6TGlmZWN5Y2xlRXhwaXJhdGlvbjoqJyxcblxuICAvKipcbiAgICogVGhlIHMzOkxpZmVjeWNsZUV4cGlyYXRpb246RGVsZXRlIGV2ZW50IHR5cGUgbm90aWZpZXMgeW91IHdoZW4gYW4gb2JqZWN0XG4gICAqIGluIGFuIHVudmVyc2lvbmVkIGJ1Y2tldCBpcyBkZWxldGVkLlxuICAgKiBJdCBhbHNvIG5vdGlmaWVzIHlvdSB3aGVuIGFuIG9iamVjdCB2ZXJzaW9uIGlzIHBlcm1hbmVudGx5IGRlbGV0ZWQgYnkgYW5cbiAgICogUzMgTGlmZWN5Y2xlIGNvbmZpZ3VyYXRpb24uXG4gICAqL1xuICBMSUZFQ1lDTEVfRVhQSVJBVElPTl9ERUxFVEUgPSAnczM6TGlmZWN5Y2xlRXhwaXJhdGlvbjpEZWxldGUnLFxuXG4gIC8qKlxuICAgKiBUaGUgczM6TGlmZWN5Y2xlRXhwaXJhdGlvbjpEZWxldGVNYXJrZXJDcmVhdGVkIGV2ZW50IHR5cGUgbm90aWZpZXMgeW91XG4gICAqIHdoZW4gUzMgTGlmZWN5Y2xlIGNyZWF0ZXMgYSBkZWxldGUgbWFya2VyIHdoZW4gYSBjdXJyZW50IHZlcnNpb24gb2YgYW5cbiAgICogb2JqZWN0IGluIHZlcnNpb25lZCBidWNrZXQgaXMgZGVsZXRlZC5cbiAgICovXG4gIExJRkVDWUNMRV9FWFBJUkFUSU9OX0RFTEVURV9NQVJLRVJfQ1JFQVRFRCA9ICdzMzpMaWZlY3ljbGVFeHBpcmF0aW9uOkRlbGV0ZU1hcmtlckNyZWF0ZWQnLFxuXG4gIC8qKlxuICAgKiBZb3UgcmVjZWl2ZSB0aGlzIG5vdGlmaWNhdGlvbiBldmVudCB3aGVuIGFuIG9iamVjdCBpcyB0cmFuc2l0aW9uZWQgdG9cbiAgICogYW5vdGhlciBBbWF6b24gUzMgc3RvcmFnZSBjbGFzcyBieSBhbiBTMyBMaWZlY3ljbGUgY29uZmlndXJhdGlvbi5cbiAgICovXG4gIExJRkVDWUNMRV9UUkFOU0lUSU9OID0gJ3MzOkxpZmVjeWNsZVRyYW5zaXRpb24nLFxuXG4gIC8qKlxuICAgKiBZb3UgcmVjZWl2ZSB0aGlzIG5vdGlmaWNhdGlvbiBldmVudCB3aGVuIGFuIG9iamVjdCB3aXRoaW4gdGhlXG4gICAqIFMzIEludGVsbGlnZW50LVRpZXJpbmcgc3RvcmFnZSBjbGFzcyBtb3ZlZCB0byB0aGUgQXJjaGl2ZSBBY2Nlc3MgdGllciBvclxuICAgKiBEZWVwIEFyY2hpdmUgQWNjZXNzIHRpZXIuXG4gICAqL1xuICBJTlRFTExJR0VOVF9USUVSSU5HID0gJ3MzOkludGVsbGlnZW50VGllcmluZycsXG5cbiAgLyoqXG4gICAqIEJ5IHVzaW5nIHRoZSBPYmplY3RUYWdnaW5nIGV2ZW50IHR5cGVzLCB5b3UgY2FuIGVuYWJsZSBub3RpZmljYXRpb24gd2hlblxuICAgKiBhbiBvYmplY3QgdGFnIGlzIGFkZGVkIG9yIGRlbGV0ZWQgZnJvbSBhbiBvYmplY3QuXG4gICAqL1xuICBPQkpFQ1RfVEFHR0lORyA9ICdzMzpPYmplY3RUYWdnaW5nOionLFxuXG4gIC8qKlxuICAgKiBUaGUgczM6T2JqZWN0VGFnZ2luZzpQdXQgZXZlbnQgdHlwZSBub3RpZmllcyB5b3Ugd2hlbiBhIHRhZyBpcyBQVVQgb24gYW5cbiAgICogb2JqZWN0IG9yIGFuIGV4aXN0aW5nIHRhZyBpcyB1cGRhdGVkLlxuXG4gICAqL1xuICBPQkpFQ1RfVEFHR0lOR19QVVQgPSAnczM6T2JqZWN0VGFnZ2luZzpQdXQnLFxuXG4gIC8qKlxuICAgKiBUaGUgczM6T2JqZWN0VGFnZ2luZzpEZWxldGUgZXZlbnQgdHlwZSBub3RpZmllcyB5b3Ugd2hlbiBhIHRhZyBpcyByZW1vdmVkXG4gICAqIGZyb20gYW4gb2JqZWN0LlxuICAgKi9cbiAgT0JKRUNUX1RBR0dJTkdfREVMRVRFID0gJ3MzOk9iamVjdFRhZ2dpbmc6RGVsZXRlJyxcblxuICAvKipcbiAgICogWW91IHJlY2VpdmUgdGhpcyBub3RpZmljYXRpb24gZXZlbnQgd2hlbiBhbiBBQ0wgaXMgUFVUIG9uIGFuIG9iamVjdCBvciB3aGVuXG4gICAqIGFuIGV4aXN0aW5nIEFDTCBpcyBjaGFuZ2VkLlxuICAgKiBBbiBldmVudCBpcyBub3QgZ2VuZXJhdGVkIHdoZW4gYSByZXF1ZXN0IHJlc3VsdHMgaW4gbm8gY2hhbmdlIHRvIGFuXG4gICAqIG9iamVjdOKAmXMgQUNMLlxuICAgKi9cbiAgT0JKRUNUX0FDTF9QVVQgPSAnczM6T2JqZWN0QWNsOlB1dCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90aWZpY2F0aW9uS2V5RmlsdGVyIHtcbiAgLyoqXG4gICAqIFMzIGtleXMgbXVzdCBoYXZlIHRoZSBzcGVjaWZpZWQgcHJlZml4LlxuICAgKi9cbiAgcmVhZG9ubHkgcHJlZml4Pzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBTMyBrZXlzIG11c3QgaGF2ZSB0aGUgc3BlY2lmaWVkIHN1ZmZpeC5cbiAgICovXG4gIHJlYWRvbmx5IHN1ZmZpeD86IHN0cmluZztcbn1cblxuLyoqXG4gKiBPcHRpb25zIGZvciB0aGUgb25DbG91ZFRyYWlsUHV0T2JqZWN0IG1ldGhvZFxuICovXG5leHBvcnQgaW50ZXJmYWNlIE9uQ2xvdWRUcmFpbEJ1Y2tldEV2ZW50T3B0aW9ucyBleHRlbmRzIGV2ZW50cy5PbkV2ZW50T3B0aW9ucyB7XG4gIC8qKlxuICAgKiBPbmx5IHdhdGNoIGNoYW5nZXMgdG8gdGhlc2Ugb2JqZWN0IHBhdGhzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gV2F0Y2ggY2hhbmdlcyB0byBhbGwgb2JqZWN0c1xuICAgKi9cbiAgcmVhZG9ubHkgcGF0aHM/OiBzdHJpbmdbXTtcbn1cblxuLyoqXG4gKiBEZWZhdWx0IGJ1Y2tldCBhY2Nlc3MgY29udHJvbCB0eXBlcy5cbiAqXG4gKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25TMy9sYXRlc3QvZGV2L2FjbC1vdmVydmlldy5odG1sXG4gKi9cbmV4cG9ydCBlbnVtIEJ1Y2tldEFjY2Vzc0NvbnRyb2wge1xuICAvKipcbiAgICogT3duZXIgZ2V0cyBGVUxMX0NPTlRST0wuIE5vIG9uZSBlbHNlIGhhcyBhY2Nlc3MgcmlnaHRzLlxuICAgKi9cbiAgUFJJVkFURSA9ICdQcml2YXRlJyxcblxuICAvKipcbiAgICogT3duZXIgZ2V0cyBGVUxMX0NPTlRST0wuIFRoZSBBbGxVc2VycyBncm91cCBnZXRzIFJFQUQgYWNjZXNzLlxuICAgKi9cbiAgUFVCTElDX1JFQUQgPSAnUHVibGljUmVhZCcsXG5cbiAgLyoqXG4gICAqIE93bmVyIGdldHMgRlVMTF9DT05UUk9MLiBUaGUgQWxsVXNlcnMgZ3JvdXAgZ2V0cyBSRUFEIGFuZCBXUklURSBhY2Nlc3MuXG4gICAqIEdyYW50aW5nIHRoaXMgb24gYSBidWNrZXQgaXMgZ2VuZXJhbGx5IG5vdCByZWNvbW1lbmRlZC5cbiAgICovXG4gIFBVQkxJQ19SRUFEX1dSSVRFID0gJ1B1YmxpY1JlYWRXcml0ZScsXG5cbiAgLyoqXG4gICAqIE93bmVyIGdldHMgRlVMTF9DT05UUk9MLiBUaGUgQXV0aGVudGljYXRlZFVzZXJzIGdyb3VwIGdldHMgUkVBRCBhY2Nlc3MuXG4gICAqL1xuICBBVVRIRU5USUNBVEVEX1JFQUQgPSAnQXV0aGVudGljYXRlZFJlYWQnLFxuXG4gIC8qKlxuICAgKiBUaGUgTG9nRGVsaXZlcnkgZ3JvdXAgZ2V0cyBXUklURSBhbmQgUkVBRF9BQ1AgcGVybWlzc2lvbnMgb24gdGhlIGJ1Y2tldC5cbiAgICogQHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUzMvbGF0ZXN0L2Rldi9TZXJ2ZXJMb2dzLmh0bWxcbiAgICovXG4gIExPR19ERUxJVkVSWV9XUklURSA9ICdMb2dEZWxpdmVyeVdyaXRlJyxcblxuICAvKipcbiAgICogT2JqZWN0IG93bmVyIGdldHMgRlVMTF9DT05UUk9MLiBCdWNrZXQgb3duZXIgZ2V0cyBSRUFEIGFjY2Vzcy5cbiAgICogSWYgeW91IHNwZWNpZnkgdGhpcyBjYW5uZWQgQUNMIHdoZW4gY3JlYXRpbmcgYSBidWNrZXQsIEFtYXpvbiBTMyBpZ25vcmVzIGl0LlxuICAgKi9cbiAgQlVDS0VUX09XTkVSX1JFQUQgPSAnQnVja2V0T3duZXJSZWFkJyxcblxuICAvKipcbiAgICogQm90aCB0aGUgb2JqZWN0IG93bmVyIGFuZCB0aGUgYnVja2V0IG93bmVyIGdldCBGVUxMX0NPTlRST0wgb3ZlciB0aGUgb2JqZWN0LlxuICAgKiBJZiB5b3Ugc3BlY2lmeSB0aGlzIGNhbm5lZCBBQ0wgd2hlbiBjcmVhdGluZyBhIGJ1Y2tldCwgQW1hem9uIFMzIGlnbm9yZXMgaXQuXG4gICAqL1xuICBCVUNLRVRfT1dORVJfRlVMTF9DT05UUk9MID0gJ0J1Y2tldE93bmVyRnVsbENvbnRyb2wnLFxuXG4gIC8qKlxuICAgKiBPd25lciBnZXRzIEZVTExfQ09OVFJPTC4gQW1hem9uIEVDMiBnZXRzIFJFQUQgYWNjZXNzIHRvIEdFVCBhbiBBbWF6b24gTWFjaGluZSBJbWFnZSAoQU1JKSBidW5kbGUgZnJvbSBBbWF6b24gUzMuXG4gICAqL1xuICBBV1NfRVhFQ19SRUFEID0gJ0F3c0V4ZWNSZWFkJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSb3V0aW5nUnVsZUNvbmRpdGlvbiB7XG4gIC8qKlxuICAgKiBUaGUgSFRUUCBlcnJvciBjb2RlIHdoZW4gdGhlIHJlZGlyZWN0IGlzIGFwcGxpZWRcbiAgICpcbiAgICogSW4gdGhlIGV2ZW50IG9mIGFuIGVycm9yLCBpZiB0aGUgZXJyb3IgY29kZSBlcXVhbHMgdGhpcyB2YWx1ZSwgdGhlbiB0aGUgc3BlY2lmaWVkIHJlZGlyZWN0IGlzIGFwcGxpZWQuXG4gICAqXG4gICAqIElmIGJvdGggY29uZGl0aW9uIHByb3BlcnRpZXMgYXJlIHNwZWNpZmllZCwgYm90aCBtdXN0IGJlIHRydWUgZm9yIHRoZSByZWRpcmVjdCB0byBiZSBhcHBsaWVkLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFRoZSBIVFRQIGVycm9yIGNvZGUgd2lsbCBub3QgYmUgdmVyaWZpZWRcbiAgICovXG4gIHJlYWRvbmx5IGh0dHBFcnJvckNvZGVSZXR1cm5lZEVxdWFscz86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIG9iamVjdCBrZXkgbmFtZSBwcmVmaXggd2hlbiB0aGUgcmVkaXJlY3QgaXMgYXBwbGllZFxuICAgKlxuICAgKiBJZiBib3RoIGNvbmRpdGlvbiBwcm9wZXJ0aWVzIGFyZSBzcGVjaWZpZWQsIGJvdGggbXVzdCBiZSB0cnVlIGZvciB0aGUgcmVkaXJlY3QgdG8gYmUgYXBwbGllZC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBUaGUgb2JqZWN0IGtleSBuYW1lIHdpbGwgbm90IGJlIHZlcmlmaWVkXG4gICAqL1xuICByZWFkb25seSBrZXlQcmVmaXhFcXVhbHM/OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBjbGFzcyBSZXBsYWNlS2V5IHtcbiAgLyoqXG4gICAqIFRoZSBzcGVjaWZpYyBvYmplY3Qga2V5IHRvIHVzZSBpbiB0aGUgcmVkaXJlY3QgcmVxdWVzdFxuICAgKi9cbiAgcHVibGljIHN0YXRpYyB3aXRoKGtleVJlcGxhY2VtZW50OiBzdHJpbmcpIHtcbiAgICByZXR1cm4gbmV3IHRoaXMoa2V5UmVwbGFjZW1lbnQpO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoZSBvYmplY3Qga2V5IHByZWZpeCB0byB1c2UgaW4gdGhlIHJlZGlyZWN0IHJlcXVlc3RcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcHJlZml4V2l0aChrZXlSZXBsYWNlbWVudDogc3RyaW5nKSB7XG4gICAgcmV0dXJuIG5ldyB0aGlzKHVuZGVmaW5lZCwga2V5UmVwbGFjZW1lbnQpO1xuICB9XG5cbiAgcHJpdmF0ZSBjb25zdHJ1Y3RvcihwdWJsaWMgcmVhZG9ubHkgd2l0aEtleT86IHN0cmluZywgcHVibGljIHJlYWRvbmx5IHByZWZpeFdpdGhLZXk/OiBzdHJpbmcpIHtcbiAgfVxufVxuXG4vKipcbiAqIFJ1bGUgdGhhdCBkZWZpbmUgd2hlbiBhIHJlZGlyZWN0IGlzIGFwcGxpZWQgYW5kIHRoZSByZWRpcmVjdCBiZWhhdmlvci5cbiAqXG4gKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25TMy9sYXRlc3QvZGV2L2hvdy10by1wYWdlLXJlZGlyZWN0Lmh0bWxcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBSb3V0aW5nUnVsZSB7XG4gIC8qKlxuICAgKiBUaGUgaG9zdCBuYW1lIHRvIHVzZSBpbiB0aGUgcmVkaXJlY3QgcmVxdWVzdFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFRoZSBob3N0IG5hbWUgdXNlZCBpbiB0aGUgb3JpZ2luYWwgcmVxdWVzdC5cbiAgICovXG4gIHJlYWRvbmx5IGhvc3ROYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgSFRUUCByZWRpcmVjdCBjb2RlIHRvIHVzZSBvbiB0aGUgcmVzcG9uc2VcbiAgICpcbiAgICogQGRlZmF1bHQgXCIzMDFcIiAtIE1vdmVkIFBlcm1hbmVudGx5XG4gICAqL1xuICByZWFkb25seSBodHRwUmVkaXJlY3RDb2RlPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBQcm90b2NvbCB0byB1c2Ugd2hlbiByZWRpcmVjdGluZyByZXF1ZXN0c1xuICAgKlxuICAgKiBAZGVmYXVsdCAtIFRoZSBwcm90b2NvbCB1c2VkIGluIHRoZSBvcmlnaW5hbCByZXF1ZXN0LlxuICAgKi9cbiAgcmVhZG9ubHkgcHJvdG9jb2w/OiBSZWRpcmVjdFByb3RvY29sO1xuXG4gIC8qKlxuICAgKiBTcGVjaWZpZXMgdGhlIG9iamVjdCBrZXkgcHJlZml4IHRvIHVzZSBpbiB0aGUgcmVkaXJlY3QgcmVxdWVzdFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFRoZSBrZXkgd2lsbCBub3QgYmUgcmVwbGFjZWRcbiAgICovXG4gIHJlYWRvbmx5IHJlcGxhY2VLZXk/OiBSZXBsYWNlS2V5O1xuXG4gIC8qKlxuICAgKiBTcGVjaWZpZXMgYSBjb25kaXRpb24gdGhhdCBtdXN0IGJlIG1ldCBmb3IgdGhlIHNwZWNpZmllZCByZWRpcmVjdCB0byBhcHBseS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyBjb25kaXRpb25cbiAgICovXG4gIHJlYWRvbmx5IGNvbmRpdGlvbj86IFJvdXRpbmdSdWxlQ29uZGl0aW9uO1xufVxuXG4vKipcbiAqIE9wdGlvbnMgZm9yIGNyZWF0aW5nIFZpcnR1YWwtSG9zdGVkIHN0eWxlIFVSTC5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBWaXJ0dWFsSG9zdGVkU3R5bGVVcmxPcHRpb25zIHtcbiAgLyoqXG4gICAqIFNwZWNpZmllcyB0aGUgVVJMIGluY2x1ZGVzIHRoZSByZWdpb24uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgcmVnaW9uYWw/OiBib29sZWFuO1xufVxuXG4vKipcbiAqIE9wdGlvbnMgZm9yIGNyZWF0aW5nIGEgVHJhbnNmZXIgQWNjZWxlcmF0aW9uIFVSTC5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBUcmFuc2ZlckFjY2VsZXJhdGlvblVybE9wdGlvbnMge1xuICAvKipcbiAgICogRHVhbC1zdGFjayBzdXBwb3J0IHRvIGNvbm5lY3QgdG8gdGhlIGJ1Y2tldCBvdmVyIElQdjYuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGR1YWxTdGFjaz86IGJvb2xlYW47XG59XG5cbmZ1bmN0aW9uIG1hcE9yVW5kZWZpbmVkPFQsIFU+KGxpc3Q6IFRbXSB8IHVuZGVmaW5lZCwgY2FsbGJhY2s6IChlbGVtZW50OiBUKSA9PiBVKTogVVtdIHwgdW5kZWZpbmVkIHtcbiAgaWYgKCFsaXN0IHx8IGxpc3QubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgfVxuXG4gIHJldHVybiBsaXN0Lm1hcChjYWxsYmFjayk7XG59XG4iXX0=