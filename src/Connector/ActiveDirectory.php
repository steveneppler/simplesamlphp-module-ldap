<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Connector;

use SimpleSAML\Logger;
use function ldap_get_option;


use SimpleSAML\Module\ldap\Error\ActiveDirectoryErrors;
use SimpleSAML\Module\ldap\Auth\InvalidCredentialResult;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;

/**
 * Extends Ldap so that we can diagnose error messages from MS Active Directory
 */
class ActiveDirectory extends Ldap
{
    public const ERR_PASSWORD_RESET = 'RESETPASSWORD';
    public const ERR_ACCOUNT_RESET = 'RESETACCOUNT';
    public const ERR_LOGON_RESTRICTION = 'LOGONRESTRICTION';

    public function bind(?string $username, #[\SensitiveParameter]?string $password): void
    {
        try {
            $this->connection->bind($username, strval($password));
        } catch (InvalidCredentialsException $e) {
            Logger::debug("LDAP bind(): InvalidCredentialsException");
            throw new Error\Error($this->resolveBindException($e), null, 401, new ActiveDirectoryErrors());
        }

        if ($username === null) {
            Logger::debug("LDAP bind(): Anonymous bind succesful.");
        } else {
            Logger::debug(sprintf("LDAP bind(): Bind successful for DN '%s'.", $username));
        }
    }


    /**
     * Resolves the bind exception
     *
     * @return string
     */
    protected function resolveBindException(InvalidCredentialsException $e): string
    {
        ldap_get_option(
            $this->adapter->getConnection()->getResource(),
            LDAP_OPT_DIAGNOSTIC_MESSAGE,
            $message,
        );

        $result  = InvalidCredentialResult::fromDiagnosticMessage($message);
        if ($result->isInvalidCredential()) {
            return self::ERR_WRONG_PASS;
        } elseif ($result->isPasswordError()) {
            return self::ERR_PASSWORD_RESET;
        } elseif ($result->isAccountError()) {
            return self::ERR_ACCOUNT_RESET;
        } elseif ($result->isRestricted()) {
            return self::ERR_LOGON_RESTRICTION;
        }

        // default to the wrong user pass
        return self::ERR_WRONG_PASS;
    }
}
