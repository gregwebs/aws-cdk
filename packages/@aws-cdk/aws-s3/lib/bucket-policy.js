"use strict";
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.BucketPolicy = void 0;
const jsiiDeprecationWarnings = require("../.warnings.jsii.js");
const JSII_RTTI_SYMBOL_1 = Symbol.for("jsii.rtti");
const aws_iam_1 = require("@aws-cdk/aws-iam");
const core_1 = require("@aws-cdk/core");
const s3_generated_1 = require("./s3.generated");
/**
 * The bucket policy for an Amazon S3 bucket
 *
 * Policies define the operations that are allowed on this resource.
 *
 * You almost never need to define this construct directly.
 *
 * All AWS resources that support resource policies have a method called
 * `addToResourcePolicy()`, which will automatically create a new resource
 * policy if one doesn't exist yet, otherwise it will add to the existing
 * policy.
 *
 * Prefer to use `addToResourcePolicy()` instead.
 */
class BucketPolicy extends core_1.Resource {
    constructor(scope, id, props) {
        super(scope, id);
        /**
         * A policy document containing permissions to add to the specified bucket.
         * For more information, see Access Policy Language Overview in the Amazon
         * Simple Storage Service Developer Guide.
         */
        this.document = new aws_iam_1.PolicyDocument();
        try {
            jsiiDeprecationWarnings._aws_cdk_aws_s3_BucketPolicyProps(props);
        }
        catch (error) {
            if (process.env.JSII_DEBUG !== "1" && error.name === "DeprecationError") {
                Error.captureStackTrace(error, BucketPolicy);
            }
            throw error;
        }
        if (!props.bucket.bucketName) {
            throw new Error('Bucket doesn\'t have a bucketName defined');
        }
        this.resource = new s3_generated_1.CfnBucketPolicy(this, 'Resource', {
            bucket: props.bucket.bucketName,
            policyDocument: this.document,
        });
        if (props.removalPolicy) {
            this.resource.applyRemovalPolicy(props.removalPolicy);
        }
    }
    /**
     * Sets the removal policy for the BucketPolicy.
     * @param removalPolicy the RemovalPolicy to set.
     */
    applyRemovalPolicy(removalPolicy) {
        this.resource.applyRemovalPolicy(removalPolicy);
    }
}
exports.BucketPolicy = BucketPolicy;
_a = JSII_RTTI_SYMBOL_1;
BucketPolicy[_a] = { fqn: "@aws-cdk/aws-s3.BucketPolicy", version: "0.0.0" };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVja2V0LXBvbGljeS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImJ1Y2tldC1wb2xpY3kudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsOENBQWtEO0FBQ2xELHdDQUF3RDtBQUd4RCxpREFBaUQ7QUFnQmpEOzs7Ozs7Ozs7Ozs7O0dBYUc7QUFDSCxNQUFhLFlBQWEsU0FBUSxlQUFRO0lBV3hDLFlBQVksS0FBZ0IsRUFBRSxFQUFVLEVBQUUsS0FBd0I7UUFDaEUsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUMsQ0FBQztRQVZuQjs7OztXQUlHO1FBQ2EsYUFBUSxHQUFHLElBQUksd0JBQWMsRUFBRSxDQUFDOzs7Ozs7K0NBUHJDLFlBQVk7Ozs7UUFjckIsSUFBSSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsVUFBVSxFQUFFO1lBQzVCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkNBQTJDLENBQUMsQ0FBQztTQUM5RDtRQUVELElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBSSw4QkFBZSxDQUFDLElBQUksRUFBRSxVQUFVLEVBQUU7WUFDcEQsTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsVUFBVTtZQUMvQixjQUFjLEVBQUUsSUFBSSxDQUFDLFFBQVE7U0FDOUIsQ0FBQyxDQUFDO1FBRUgsSUFBSSxLQUFLLENBQUMsYUFBYSxFQUFFO1lBQ3ZCLElBQUksQ0FBQyxRQUFRLENBQUMsa0JBQWtCLENBQUMsS0FBSyxDQUFDLGFBQWEsQ0FBQyxDQUFDO1NBQ3ZEO0tBQ0Y7SUFFRDs7O09BR0c7SUFDSSxrQkFBa0IsQ0FBQyxhQUE0QjtRQUNwRCxJQUFJLENBQUMsUUFBUSxDQUFDLGtCQUFrQixDQUFDLGFBQWEsQ0FBQyxDQUFDO0tBQ2pEOztBQWxDSCxvQ0FvQ0MiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBQb2xpY3lEb2N1bWVudCB9IGZyb20gJ0Bhd3MtY2RrL2F3cy1pYW0nO1xuaW1wb3J0IHsgUmVtb3ZhbFBvbGljeSwgUmVzb3VyY2UgfSBmcm9tICdAYXdzLWNkay9jb3JlJztcbmltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gJ2NvbnN0cnVjdHMnO1xuaW1wb3J0IHsgSUJ1Y2tldCB9IGZyb20gJy4vYnVja2V0JztcbmltcG9ydCB7IENmbkJ1Y2tldFBvbGljeSB9IGZyb20gJy4vczMuZ2VuZXJhdGVkJztcblxuZXhwb3J0IGludGVyZmFjZSBCdWNrZXRQb2xpY3lQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgQW1hem9uIFMzIGJ1Y2tldCB0aGF0IHRoZSBwb2xpY3kgYXBwbGllcyB0by5cbiAgICovXG4gIHJlYWRvbmx5IGJ1Y2tldDogSUJ1Y2tldDtcblxuICAvKipcbiAgICogUG9saWN5IHRvIGFwcGx5IHdoZW4gdGhlIHBvbGljeSBpcyByZW1vdmVkIGZyb20gdGhpcyBzdGFjay5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBSZW1vdmFsUG9saWN5LkRFU1RST1kuXG4gICAqL1xuICByZWFkb25seSByZW1vdmFsUG9saWN5PzogUmVtb3ZhbFBvbGljeTtcbn1cblxuLyoqXG4gKiBUaGUgYnVja2V0IHBvbGljeSBmb3IgYW4gQW1hem9uIFMzIGJ1Y2tldFxuICpcbiAqIFBvbGljaWVzIGRlZmluZSB0aGUgb3BlcmF0aW9ucyB0aGF0IGFyZSBhbGxvd2VkIG9uIHRoaXMgcmVzb3VyY2UuXG4gKlxuICogWW91IGFsbW9zdCBuZXZlciBuZWVkIHRvIGRlZmluZSB0aGlzIGNvbnN0cnVjdCBkaXJlY3RseS5cbiAqXG4gKiBBbGwgQVdTIHJlc291cmNlcyB0aGF0IHN1cHBvcnQgcmVzb3VyY2UgcG9saWNpZXMgaGF2ZSBhIG1ldGhvZCBjYWxsZWRcbiAqIGBhZGRUb1Jlc291cmNlUG9saWN5KClgLCB3aGljaCB3aWxsIGF1dG9tYXRpY2FsbHkgY3JlYXRlIGEgbmV3IHJlc291cmNlXG4gKiBwb2xpY3kgaWYgb25lIGRvZXNuJ3QgZXhpc3QgeWV0LCBvdGhlcndpc2UgaXQgd2lsbCBhZGQgdG8gdGhlIGV4aXN0aW5nXG4gKiBwb2xpY3kuXG4gKlxuICogUHJlZmVyIHRvIHVzZSBgYWRkVG9SZXNvdXJjZVBvbGljeSgpYCBpbnN0ZWFkLlxuICovXG5leHBvcnQgY2xhc3MgQnVja2V0UG9saWN5IGV4dGVuZHMgUmVzb3VyY2Uge1xuXG4gIC8qKlxuICAgKiBBIHBvbGljeSBkb2N1bWVudCBjb250YWluaW5nIHBlcm1pc3Npb25zIHRvIGFkZCB0byB0aGUgc3BlY2lmaWVkIGJ1Y2tldC5cbiAgICogRm9yIG1vcmUgaW5mb3JtYXRpb24sIHNlZSBBY2Nlc3MgUG9saWN5IExhbmd1YWdlIE92ZXJ2aWV3IGluIHRoZSBBbWF6b25cbiAgICogU2ltcGxlIFN0b3JhZ2UgU2VydmljZSBEZXZlbG9wZXIgR3VpZGUuXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgZG9jdW1lbnQgPSBuZXcgUG9saWN5RG9jdW1lbnQoKTtcblxuICBwcml2YXRlIHJlc291cmNlOiBDZm5CdWNrZXRQb2xpY3k7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IEJ1Y2tldFBvbGljeVByb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcblxuICAgIGlmICghcHJvcHMuYnVja2V0LmJ1Y2tldE5hbWUpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQnVja2V0IGRvZXNuXFwndCBoYXZlIGEgYnVja2V0TmFtZSBkZWZpbmVkJyk7XG4gICAgfVxuXG4gICAgdGhpcy5yZXNvdXJjZSA9IG5ldyBDZm5CdWNrZXRQb2xpY3kodGhpcywgJ1Jlc291cmNlJywge1xuICAgICAgYnVja2V0OiBwcm9wcy5idWNrZXQuYnVja2V0TmFtZSxcbiAgICAgIHBvbGljeURvY3VtZW50OiB0aGlzLmRvY3VtZW50LFxuICAgIH0pO1xuXG4gICAgaWYgKHByb3BzLnJlbW92YWxQb2xpY3kpIHtcbiAgICAgIHRoaXMucmVzb3VyY2UuYXBwbHlSZW1vdmFsUG9saWN5KHByb3BzLnJlbW92YWxQb2xpY3kpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBTZXRzIHRoZSByZW1vdmFsIHBvbGljeSBmb3IgdGhlIEJ1Y2tldFBvbGljeS5cbiAgICogQHBhcmFtIHJlbW92YWxQb2xpY3kgdGhlIFJlbW92YWxQb2xpY3kgdG8gc2V0LlxuICAgKi9cbiAgcHVibGljIGFwcGx5UmVtb3ZhbFBvbGljeShyZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5KSB7XG4gICAgdGhpcy5yZXNvdXJjZS5hcHBseVJlbW92YWxQb2xpY3kocmVtb3ZhbFBvbGljeSk7XG4gIH1cblxufVxuIl19